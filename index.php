<?php
/**
 * CMSimple_XH plugin "2fa": TOTP (Google Authenticator) second factor for the admin login.
 *
 * After the password login succeeds, the backend shows a code prompt before any
 * admin page or action runs. Setup is done only in the backend (Plugins -> 2fa):
 * until it is complete, the admin goes straight to that page to enroll.
 *
 * Folder name starts with "2" so this plugin loads before other plugins.
 */

if (!defined('CMSIMPLE_XH_VERSION')) {
    return;
}

/** Path of the data file (TOTP secret and rate-limit state). */
function twofa_data_file(): string
{
    return __DIR__ . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'twofa.php';
}

/** @return array<string, mixed> */
function twofa_load(): array
{
    $file = twofa_data_file();
    if (!is_file($file)) {
        return [];
    }
    $data = include $file;
    return is_array($data) ? $data : [];
}

/** @param array<string, mixed> $data */
function twofa_save(array $data): bool
{
    $dir = dirname(twofa_data_file());
    if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
        return false;
    }
    // The file returns an array, so a direct HTTP request prints nothing.
    $php = "<?php\nreturn " . var_export($data, true) . ";\n";
    return file_put_contents(twofa_data_file(), $php, LOCK_EX) !== false;
}

/** Returns a safe relative URI (path + optional query) to prevent open redirects. */
function twofa_safe_uri(): string
{
    $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
    $parts = parse_url($uri);
    $path = $parts['path'] ?? '/';
    if ($path === '' || $path[0] !== '/') {
        $path = '/' . ltrim($path, '/');
    }
    return $path . (isset($parts['query']) ? '?' . $parts['query'] : '');
}

/**
 * Returns a localized plugin string from $plugin_tx['2fa'], with English fallback.
 */
function twofa_tx(string $key, string $fallback): string
{
    global $plugin_tx;
    if (isset($plugin_tx['2fa'][$key]) && is_string($plugin_tx['2fa'][$key]) && $plugin_tx['2fa'][$key] !== '') {
        return $plugin_tx['2fa'][$key];
    }
    return $fallback;
}

/**
 * Records a failed verification attempt and locks for 15 minutes after 5 fails.
 *
 * @param array<string, mixed> $data
 */
function twofa_record_failure(array &$data): void
{
    usleep(300000);
    $data['fails'] = (int) ($data['fails'] ?? 0) + 1;
    if ($data['fails'] >= 5) {
        $data['fails'] = 0;
        $data['locked_until'] = time() + 900;
    }
    twofa_save($data);
}

/** True while the failed-attempt lock is active. */
function twofa_is_locked(array $data): bool
{
    return time() < (int) ($data['locked_until'] ?? 0);
}

function twofa_base32_decode(string $input): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $input = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $input));
    $bits = '';
    for ($i = 0, $n = strlen($input); $i < $n; $i++) {
        $bits .= str_pad(decbin((int) strpos($alphabet, $input[$i])), 5, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) === 8) {
            $out .= chr((int) bindec($byte));
        }
    }
    return $out;
}

function twofa_base32_encode(string $bin): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    for ($i = 0, $n = strlen($bin); $i < $n; $i++) {
        $bits .= str_pad(decbin(ord($bin[$i])), 8, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 5) as $chunk) {
        $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
        $out .= $alphabet[(int) bindec($chunk)];
    }
    return $out;
}

/** 160-bit secret, the size Google Authenticator expects. */
function twofa_new_secret(): string
{
    return twofa_base32_encode(random_bytes(20));
}

/** otpauth:// URI for the authenticator app (QR code content). */
function twofa_otpauth(string $secret): string
{
    $host = (string) ($_SERVER['HTTP_HOST'] ?? 'CMSimple');
    $label = rawurlencode('CMSimple admin @ ' . $host);
    return 'otpauth://totp/' . $label . '?secret=' . $secret
        . '&issuer=' . rawurlencode($host) . '&algorithm=SHA1&digits=6&period=30';
}

/** RFC 6238 TOTP: HMAC-SHA1, 30-second step, 6 digits. */
function twofa_totp(string $secret, int $step): string
{
    $key = twofa_base32_decode($secret);
    $hash = hash_hmac('sha1', pack('J', $step), $key, true);
    $offset = ord($hash[19]) & 0x0f;
    $code = ((ord($hash[$offset]) & 0x7f) << 24)
        | ((ord($hash[$offset + 1]) & 0xff) << 16)
        | ((ord($hash[$offset + 2]) & 0xff) << 8)
        | (ord($hash[$offset + 3]) & 0xff);
    return str_pad((string) ($code % 1000000), 6, '0', STR_PAD_LEFT);
}

/**
 * Returns the matched time step, or null. Accepts one step of clock drift
 * either way, and refuses steps at or before $lastStep (no code reuse).
 */
function twofa_verify(string $secret, string $code, int $lastStep): ?int
{
    $code = preg_replace('/\s+/', '', $code);
    if (!preg_match('/^\d{6}$/', $code)) {
        return null;
    }
    $now = intdiv(time(), 30);
    for ($step = $now - 1; $step <= $now + 1; $step++) {
        if ($step > $lastStep && hash_equals(twofa_totp($secret, $step), $code)) {
            return $step;
        }
    }
    return null;
}

/**
 * Returns HTML tags that load js/qrcode.js externally and draw the otpauth URI
 * inside #twofa-qr in the browser, so the secret never goes to an outside service.
 */
function twofa_qr_tags(string $otpauth): string
{
    global $pth;
    $jsFile = __DIR__ . DIRECTORY_SEPARATOR . 'js' . DIRECTORY_SEPARATOR . 'qrcode.js';
    $missingMsg = json_encode(
        twofa_tx('qr_missing', 'QR code not shown: plugins/2fa/js/qrcode.js is missing or unreadable. Use the setup key below.'),
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
    );
    if (!is_file($jsFile)) {
        return '<script>document.getElementById("twofa-qr").textContent=' . $missingMsg . ';</script>';
    }
    $basePlugins = isset($pth['folder']['plugins']) ? $pth['folder']['plugins'] : './plugins/';
    $jsUrl = XH_hsc($basePlugins . '2fa/js/qrcode.js');
    $uri = json_encode($otpauth, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    return '<script src="' . $jsUrl . '"></script>'
        . '<script>(function(){try{if(typeof qrcode==="undefined"){throw "library not loaded";}'
        . 'var q=qrcode(0,"M");q.addData(' . $uri . ');q.make();'
        . 'document.getElementById("twofa-qr").innerHTML=q.createSvgTag({scalable:true,margin:2});}'
        . 'catch(e){document.getElementById("twofa-qr").textContent=' . $missingMsg . ';}})();</script>';
}

/**
 * Creates 10 one-time backup codes. Only their hashes are stored in $data;
 * the plain codes are returned so they can be shown to the admin once.
 *
 * @param array<string, mixed> $data
 * @return list<string>
 */
function twofa_make_backup_codes(array &$data): array
{
    $codes = [];
    $hashes = [];
    for ($i = 0; $i < 10; $i++) {
        $raw = bin2hex(random_bytes(5)); // 10 lowercase hex characters
        $codes[] = substr($raw, 0, 5) . '-' . substr($raw, 5, 5);
        $hashes[] = password_hash($raw, PASSWORD_DEFAULT);
    }
    $data['backup_hashes'] = $hashes;
    return $codes;
}

/**
 * Checks a backup code (dashes and case are ignored). A matching code is
 * removed, so it works only once.
 *
 * @param array<string, mixed> $data
 */
function twofa_use_backup_code(array &$data, string $input): bool
{
    $raw = strtolower((string) preg_replace('/[^A-Za-z0-9]/', '', $input));
    if (strlen($raw) !== 10 || empty($data['backup_hashes'])) {
        return false;
    }
    foreach ($data['backup_hashes'] as $i => $hash) {
        if (password_verify($raw, $hash)) {
            unset($data['backup_hashes'][$i]);
            $data['backup_hashes'] = array_values($data['backup_hashes']);
            return true;
        }
    }
    return false;
}

/**
 * Renders the code prompt and exits. Only used once setup is complete.
 */
function twofa_challenge(): void
{
    $data = twofa_load();
    $secret = (string) ($data['secret'] ?? '');
    $message = '';
    $safeUri = twofa_safe_uri();

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['twofa_code']) && is_string($_POST['twofa_code'])) {
        if (twofa_is_locked($data)) {
            $message = twofa_tx('err_locked', 'Too many failed attempts. Try again in a few minutes.');
        } else {
            $lastStep = (int) ($data['last_step'] ?? -1);
            $step = twofa_verify($secret, $_POST['twofa_code'], $lastStep);
            $usedBackup = $step === null && twofa_use_backup_code($data, $_POST['twofa_code']);
            if ($step !== null || $usedBackup) {
                if ($step !== null) {
                    $data['last_step'] = $step;
                }
                $data['fails'] = 0;
                $data['locked_until'] = 0;
                if (twofa_save($data)) {
                    session_regenerate_id(true);
                    $_SESSION['twofa_ok'] = true;
                    header('Location: ' . $safeUri, true, 303);
                    exit;
                }
                $message = twofa_tx(
                    'err_save',
                    'Could not save the two-factor data. Check that plugins/2fa/data is writable.'
                );
            } else {
                twofa_record_failure($data);
                $message = twofa_tx('err_invalid', 'The code is incorrect or was already used.');
            }
        }
    }

    $pageTitle = twofa_tx('page_title', 'Two-factor check');
    $heading = twofa_tx('heading', 'Two-factor authentication');

    $html = '<!DOCTYPE html><html><head><meta charset="utf-8">'
        . '<meta name="robots" content="noindex"><title>' . XH_hsc($pageTitle) . '</title></head>'
        . '<body style="font-family:sans-serif;max-width:36em;margin:3em auto;padding:0 1em">'
        . '<h1>' . XH_hsc($heading) . '</h1>';
    if ($message !== '') {
        $html .= '<p><b>' . XH_hsc($message) . '</b></p>';
    }
    $promptText = twofa_tx(
        'prompt_enter',
        'Enter the 6-digit code from Google Authenticator, or one of your backup codes.'
    );
    $verifyBtn = twofa_tx('btn_verify', 'Verify');
    $logoutLink = twofa_tx('link_logout', 'Log out');

    $html .= '<p>' . XH_hsc($promptText) . '</p>'
        . '<form method="post" action="' . XH_hsc($safeUri) . '">'
        . '<input type="text" name="twofa_code" autocomplete="one-time-code"'
        . ' maxlength="11" required autofocus size="12"> '
        . '<button type="submit">' . XH_hsc($verifyBtn) . '</button></form>'
        . '<p><a href="' . XH_hsc(CMSIMPLE_URL . '?&logout') . '">' . XH_hsc($logoutLink) . '</a></p>'
        . '</body></html>';

    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store');
    echo $html;
    exit;
}

/**
 * Gate: runs on every plugin load.
 *
 * - Anonymous visitors: no effect.
 * - A password POST (keycut) clears any earlier verification, so a new login
 *   always needs a fresh code.
 * - A logout request ends the admin session here and redirects, so no admin
 *   action can run in the same request.
 * - Admins who have not finished setup go straight to the backend (Plugins -> 2fa),
 *   where enrollment happens. No code is asked until setup is complete.
 * - Logged-in admins without a verified code get the code prompt instead of the
 *   backend. The prompt exits before any admin action runs.
 */
function twofa_run(): void
{
    global $logout;

    if (!XH_ADM && !isset($_POST['keycut'])) {
        return;
    }
    XH_startSession();
    $isLogout = !empty($logout) || isset($_GET['logout']);
    if (isset($_POST['keycut'])) {
        unset($_SESSION['twofa_ok'], $_SESSION['twofa_pending']);
    }
    if ($isLogout) {
        if (XH_ADM) {
            unset($_SESSION['xh_password'], $_SESSION['xh_user_agent'],
                $_SESSION['twofa_ok'], $_SESSION['twofa_pending'], $_SESSION['twofa_new_codes']);
            session_regenerate_id(true);
            header('Location: ' . CMSIMPLE_URL, true, 303);
            exit;
        }
        return;
    }
    if (!XH_ADM || !empty($_SESSION['twofa_ok'])) {
        return;
    }
    // Setup not finished yet: no code is asked, so the admin can reach Plugins -> 2fa.
    $data = twofa_load();
    if (empty($data['secret'])) {
        return;
    }
    twofa_challenge();
}

twofa_run();
