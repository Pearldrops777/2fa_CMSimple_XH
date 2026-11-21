<?php
/**
 * CMSimple_XH plugin "2fa": TOTP (Google Authenticator) second factor for the admin login.
 *
 * After the password login succeeds, the backend shows a code prompt before any
 * admin page or action runs. First use shows an enrollment screen with the key.
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
 * Returns JavaScript that draws the otpauth URI as a QR code in #twofa-qr.
 * The renderer (qrcode-generator, MIT) ships in js/qrcode.js and runs in the
 * browser, so the secret never goes to an outside service.
 */
function twofa_qr_script(string $otpauth): string
{
    $lib = (string) @file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . 'js' . DIRECTORY_SEPARATOR . 'qrcode.js');
    if ($lib === '') {
        return '';
    }
    $uri = json_encode($otpauth, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    return $lib . "\n;(function(){var q=qrcode(0,'M');q.addData(" . $uri . ");q.make();"
        . "document.getElementById('twofa-qr').innerHTML=q.createSvgTag({scalable:true,margin:2});})();";
}

/**
 * Renders the code prompt (or enrollment screen) and exits.
 */
function twofa_challenge(): void
{
    $data = twofa_load();
    $enrolling = empty($data['secret']);
    $message = '';

    if ($enrolling) {
        if (empty($_SESSION['twofa_pending'])) {
            $_SESSION['twofa_pending'] = twofa_new_secret();
        }
        $secret = (string) $_SESSION['twofa_pending'];
    } else {
        $secret = (string) $data['secret'];
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['twofa_code']) && is_string($_POST['twofa_code'])) {
        $lockedUntil = (int) ($data['locked_until'] ?? 0);
        if (time() < $lockedUntil) {
            $message = 'Too many failed attempts. Try again in a few minutes.';
        } else {
            $lastStep = $enrolling ? -1 : (int) ($data['last_step'] ?? -1);
            $step = twofa_verify($secret, $_POST['twofa_code'], $lastStep);
            if ($step !== null) {
                $data['secret'] = $secret;
                $data['last_step'] = $step;
                $data['fails'] = 0;
                $data['locked_until'] = 0;
                if (twofa_save($data)) {
                    unset($_SESSION['twofa_pending']);
                    $_SESSION['twofa_ok'] = true;
                    header('Location: ' . $_SERVER['REQUEST_URI'], true, 303);
                    exit;
                }
                $message = 'Could not save the two-factor data. Check that plugins/2fa/data is writable.';
            } else {
                $data['fails'] = (int) ($data['fails'] ?? 0) + 1;
                if ($data['fails'] >= 5) {
                    $data['fails'] = 0;
                    $data['locked_until'] = time() + 900;
                }
                twofa_save($data);
                $message = 'The code is incorrect or was already used.';
            }
        }
    }

    $host = (string) ($_SERVER['HTTP_HOST'] ?? 'CMSimple');
    $label = rawurlencode('CMSimple admin @ ' . $host);
    $otpauth = 'otpauth://totp/' . $label . '?secret=' . $secret
        . '&issuer=' . rawurlencode($host) . '&algorithm=SHA1&digits=6&period=30';

    $html = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        . '<meta name="robots" content="noindex"><title>Two-factor check</title></head>'
        . '<body style="font-family:sans-serif;max-width:36em;margin:3em auto;padding:0 1em">'
        . '<h1>Two-factor authentication</h1>';
    if ($message !== '') {
        $html .= '<p><b>' . XH_hsc($message) . '</b></p>';
    }
    if ($enrolling) {
        $html .= '<p>Scan this QR code with Google Authenticator (tap + and choose &quot;Scan a QR code&quot;).</p>'
            . '<div id="twofa-qr" style="width:220px;height:220px"></div>'
            . '<p>Cannot scan? Choose &quot;Enter a setup key&quot; and type: '
            . '<code style="font-size:1.1em">' . XH_hsc(trim(chunk_split($secret, 4, ' '))) . '</code></p>'
            . '<p>Then enter the 6-digit code it shows to finish.</p>'
            . '<script>' . twofa_qr_script($otpauth) . '</script>';
    } else {
        $html .= '<p>Enter the 6-digit code from Google Authenticator.</p>';
    }
    $html .= '<form method="post" action="' . XH_hsc((string) $_SERVER['REQUEST_URI']) . '">'
        . '<input type="text" name="twofa_code" inputmode="numeric" autocomplete="one-time-code"'
        . ' pattern="[0-9 ]{6,7}" maxlength="7" required autofocus size="10"> '
        . '<button type="submit">Verify</button></form>'
        . '<p><a href="' . XH_hsc(CMSIMPLE_URL . '?&logout') . '">Log out</a></p>'
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
 * - Logged-in admins without a verified code get the challenge instead of the
 *   backend. The challenge exits before any admin action runs.
 */
function twofa_run(): void
{
    if (!XH_ADM && !isset($_POST['keycut'])) {
        return;
    }
    XH_startSession();
    if (isset($_POST['keycut'])) {
        unset($_SESSION['twofa_ok']);
    }
    if (!XH_ADM || !empty($_SESSION['twofa_ok'])) {
        return;
    }
    twofa_challenge();
}

twofa_run();
