<?php
/**
 * CMSimple_XH plugin "2fa": Backend administration panel.
 *
 * Accessible via Plugins -> 2fa in the CMSimple_XH admin menu.
 * Setup (QR code, key and first code, then backup codes) is done here.
 * Once set up, this page also allows viewing the remaining backup code count,
 * regenerating backup codes, and resetting the TOTP secret. Language strings are
 * edited via CMSimple_XH's standard plugin language editor.
 */

if (!defined('CMSIMPLE_XH_VERSION')) {
    return;
}

global $admin, $action, $plugin, $o;

XH_registerStandardPluginMenuItems(false);

if (function_exists('XH_registerPluginMenuItem')) {
    XH_registerPluginMenuItem(
        '2fa',
        twofa_tx('access_menu', 'Check for Access Protection'),
        '?&2fa&twofa_check=1',
        ''
    );
}

if (function_exists('XH_wantsPluginAdministration') && XH_wantsPluginAdministration('2fa')) {
    $o .= print_plugin_admin('off');
    switch ((string) $admin) {
        case '':
            $o .= twofa_admin_view();
            break;
        default:
            $o .= plugin_admin_common((string) $action, (string) $admin, (string) $plugin);
            break;
    }
}

/**
 * Checks the whole plugin folder for access protection:
 * - web access to the plugin folder (no directory listing) and to data/ and data/twofa.php,
 * - no file or folder in plugins/2fa is writable by other users,
 * - the secret file is not readable by other users,
 * - PHP can write to data/.
 *
 * @return list<array{0: bool|null, 1: string}> true = OK, false = problem, null = not tested
 */
function twofa_access_check(): array
{
    $results = [];
    $file = twofa_data_file();
    $dir = dirname($file);
    $pluginDir = dirname($dir);
    $base = twofa_site_base() . '/plugins/2fa/';

    // Web access: data/ and data/twofa.php must not be served.
    foreach (['data/', 'data/twofa.php'] as $rel) {
        $label = 'plugins/2fa/' . $rel;
        $status = twofa_http_get($base . $rel)['status'];
        if ($status === 0) {
            $results[] = [null, str_replace('{path}', $label, twofa_tx(
                'access_web_unknown',
                'Web access to {path} could not be tested from the server. Check in a browser that it cannot be opened.'
            ))];
        } elseif ($status === 403 || $status === 404) {
            $results[] = [true, str_replace(['{path}', '{status}'], [$label, (string) $status], twofa_tx(
                'access_web_ok',
                'Web access to {path} is blocked (HTTP {status}).'
            ))];
        } else {
            $results[] = [false, str_replace(['{path}', '{status}'], [$label, (string) $status], twofa_tx(
                'access_web_fail',
                '{path} is reachable over the web (HTTP {status}). Block web access to it, see addendum.txt.'
            ))];
        }
    }

    // Web access: the plugin folder itself must not show a directory listing.
    $folder = twofa_http_get($base);
    if ($folder['status'] === 0) {
        $results[] = [null, twofa_tx(
            'access_listing_unknown',
            'The plugin folder could not be checked for a directory listing from the server. Check in a browser that plugins/2fa/ shows no file list.'
        )];
    } elseif (stripos($folder['body'], 'Index of') !== false) {
        $results[] = [false, twofa_tx(
            'access_listing_fail',
            'plugins/2fa/ shows a directory listing. Disable directory listing, see addendum.txt.'
        )];
    } else {
        $results[] = [true, twofa_tx(
            'access_listing_ok',
            'plugins/2fa/ shows no directory listing.'
        )];
    }

    // Whole plugin folder: nothing may be writable by other users.
    $problems = [];
    $count = 0;
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($pluginDir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iterator as $path => $unused) {
            $count++;
            if (fileperms($path) & 0002) {
                $rel = 'plugins/2fa/' . str_replace('\\', '/', substr($path, strlen($pluginDir) + 1));
                $problems[] = [false, str_replace('{path}', $rel, twofa_tx(
                    'access_world_writable',
                    '{path} is writable by other users. Remove write access for others, see addendum.txt.'
                ))];
            }
        }
    } catch (UnexpectedValueException $e) {
        $problems[] = [null, twofa_tx('access_folder_unreadable', 'The plugin folder could not be read, so its files were not checked.')];
    }
    if (empty($problems)) {
        $results[] = [true, str_replace('{count}', (string) $count, twofa_tx(
            'access_folder_ok',
            'Checked {count} files and folders in plugins/2fa. None are writable by other users.'
        ))];
    } else {
        $results[] = [false, str_replace(['{count}', '{problems}'], [(string) $count, (string) count($problems)], twofa_tx(
            'access_folder_fail',
            'Checked {count} files and folders in plugins/2fa. {problems} problem(s) found, listed below.'
        ))];
        $results = array_merge($results, $problems);
    }

    // Secret file and data folder: other users must not be able to read them.
    if (is_dir($dir)) {
        $ok = (fileperms($dir) & 0007) === 0;
        $results[] = [$ok, twofa_tx(
            $ok ? 'access_perm_dir_ok' : 'access_perm_dir_fail',
            $ok ? 'The data/ folder is not accessible to other users on the server.'
                : 'The data/ folder is accessible to other users. Set its mode to 700, see addendum.txt.'
        )];
    } else {
        $results[] = [null, twofa_tx('access_no_dir', 'The data/ folder does not exist yet. It is created during setup.')];
    }
    if (is_file($file)) {
        $ok = (fileperms($file) & 0077) === 0;
        $results[] = [$ok, twofa_tx(
            $ok ? 'access_perm_file_ok' : 'access_perm_file_fail',
            $ok ? 'twofa.php is accessible only to its owner.'
                : 'twofa.php is accessible to other users. Set its mode to 600, see addendum.txt.'
        )];
    } else {
        $results[] = [null, twofa_tx('access_no_file', 'twofa.php does not exist yet. It is created during setup.')];
    }

    // PHP must be able to save the secret and the rate-limit state.
    if (is_dir($dir)) {
        $writable = is_writable($dir);
        $results[] = [$writable, twofa_tx(
            $writable ? 'access_write_ok' : 'access_write_fail',
            $writable ? 'PHP can write to data/.' : 'PHP cannot write to data/. See addendum.txt.'
        )];
    }

    return $results;
}

/** HTTP status and body of a URL on this site (status 0 if it could not be requested). */
function twofa_http_get(string $url): array
{
    $ctx = stream_context_create(['http' => ['timeout' => 5, 'ignore_errors' => true]]);
    $body = @file_get_contents($url, false, $ctx);
    $status = 0;
    if (isset($http_response_header[0]) && preg_match('#\s(\d{3})\s#', $http_response_header[0], $m)) {
        $status = (int) $m[1];
    }
    return ['status' => $status, 'body' => is_string($body) ? $body : ''];
}

/** Base URL of this CMSimple_XH site, e.g. https://example.com. */
function twofa_site_base(): string
{
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $base = rtrim(dirname((string) ($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
    return $scheme . '://' . (string) ($_SERVER['HTTP_HOST'] ?? 'localhost') . $base;
}

/**
 * Renders the access check results (if any) and the button that runs the check.
 *
 * @param list<array{0: bool|null, 1: string}>|null $check
 */
function twofa_access_html($check, string $actionUrl, string $csrfField): string
{
    $html = '<div class="twofa-access"><h2>' . XH_hsc(twofa_tx('access_heading', 'Access protection check')) . '</h2>';
    if (is_array($check)) {
        $html .= '<ul>';
        foreach ($check as $item) {
            $ok = $item[0];
            $mark = $ok === true ? '&#10004;' : ($ok === false ? '&#10008;' : '?');
            $html .= '<li>' . $mark . ' ' . XH_hsc($item[1]) . '</li>';
        }
        $html .= '</ul>';
    }
    $html .= '<form method="post" action="' . $actionUrl . '">' . $csrfField
        . '<input type="hidden" name="twofa_admin_action" value="access_check">'
        . '<button type="submit">' . XH_hsc(twofa_tx('access_btn', 'Run check')) . '</button></form>';
    $html .= '</div><hr>';
    return $html;
}

/**
 * Renders setup (if not enrolled yet) or the 2FA status, backup-code
 * regeneration, and secret-reset form.
 */
function twofa_admin_view(): string
{
    global $_XH_csrfProtection;

    XH_startSession();
    $data = twofa_load();
    $hasSecret = !empty($data['secret']);
    $remaining = isset($data['backup_hashes']) && is_array($data['backup_hashes'])
        ? count($data['backup_hashes'])
        : 0;

    $message = '';
    $error = '';
    $newCodes = [];
    $check = null;
    if (isset($_GET['twofa_check'])) {
        $check = twofa_access_check();
    }

    $actionUrl = XH_hsc(twofa_safe_uri());
    $csrfField = (isset($_XH_csrfProtection) && is_object($_XH_csrfProtection))
        ? $_XH_csrfProtection->tokenInput()
        : '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['twofa_admin_action'])) {
        if (isset($_XH_csrfProtection) && is_object($_XH_csrfProtection)) {
            $_XH_csrfProtection->check();
        }

        $act = (string) $_POST['twofa_admin_action'];

        if ($act === 'access_check') {
            $check = twofa_access_check();
        } elseif ($act === 'enroll') {
            if ($hasSecret) {
                $error = twofa_tx('admin_already_enrolled', 'Two-factor authentication is already set up.');
            } elseif (twofa_is_locked($data)) {
                $error = twofa_tx('error_locked', 'Too many failed attempts. Try again in a few minutes.');
            } elseif (!isset($_POST['twofa_confirm_code']) || !is_string($_POST['twofa_confirm_code'])) {
                $error = twofa_tx('admin_enter_code', 'Please enter your current 6-digit authenticator code to confirm.');
            } else {
                $pending = (string) ($_SESSION['twofa_pending'] ?? '');
                if ($pending === '') {
                    $error = twofa_tx(
                        'admin_enroll_expired',
                        'The setup key has expired. Reload this page and scan the new QR code.'
                    );
                } elseif (($step = twofa_verify($pending, $_POST['twofa_confirm_code'], -1)) === null) {
                    twofa_record_failure($data);
                    $error = twofa_tx('error_invalid', 'The code is incorrect or was already used.');
                } else {
                    $data['secret'] = $pending;
                    $data['last_step'] = $step;
                    $data['fails'] = 0;
                    $data['locked_until'] = 0;
                    $codes = twofa_make_backup_codes($data);
                    if (twofa_save($data)) {
                        unset($_SESSION['twofa_pending']);
                        $_SESSION['twofa_new_codes'] = $codes;
                        $_SESSION['twofa_ok'] = true;
                        session_regenerate_id(true);
                        header('Location: ' . twofa_safe_uri(), true, 303);
                        exit;
                    }
                    $error = twofa_tx(
                        'error_save_failed',
                        'Could not save the two-factor data. Check that plugins/2fa/data is writable.'
                    );
                }
            }
        } elseif (!$hasSecret) {
            $error = twofa_tx('admin_not_enrolled', 'Two-factor authentication is not enrolled yet.');
        } elseif (twofa_is_locked($data)) {
            $error = twofa_tx('error_locked', 'Too many failed attempts. Try again in a few minutes.');
        } elseif (!isset($_POST['twofa_confirm_code']) || !is_string($_POST['twofa_confirm_code'])) {
            $error = twofa_tx('admin_enter_code', 'Please enter your current 6-digit authenticator code to confirm.');
        } else {
            $secret = (string) $data['secret'];
            $lastStep = (int) ($data['last_step'] ?? -1);
            $step = twofa_verify($secret, $_POST['twofa_confirm_code'], $lastStep);
            $usedBackup = ($step === null && $act === 'reset')
                ? twofa_use_backup_code($data, $_POST['twofa_confirm_code'])
                : false;

            if ($step === null && !$usedBackup) {
                twofa_record_failure($data);
                $error = twofa_tx('error_invalid', 'The code is incorrect or was already used.');
            } elseif ($act === 'regenerate') {
                if ($step !== null) {
                    $data['last_step'] = $step;
                }
                $data['fails'] = 0;
                $data['locked_until'] = 0;
                $newCodes = twofa_make_backup_codes($data);
                if (twofa_save($data)) {
                    $remaining = count($data['backup_hashes']);
                    $message = twofa_tx(
                        'admin_regen_success',
                        '10 new backup codes have been generated. All previous backup codes are now invalid.'
                    );
                } else {
                    $newCodes = [];
                    $error = twofa_tx(
                        'error_save_failed',
                        'Could not save the two-factor data. Check that plugins/2fa/data is writable.'
                    );
                }
            } elseif ($act === 'reset') {
                $file = twofa_data_file();
                $removed = !is_file($file) || @unlink($file);
                if (!$removed) {
                    $removed = twofa_save([]);
                }
                if ($removed) {
                    unset($_SESSION['twofa_ok'], $_SESSION['twofa_pending'], $_SESSION['twofa_new_codes']);
                    header('Location: ' . twofa_safe_uri(), true, 303);
                    exit;
                }
                $error = twofa_tx(
                    'error_save_failed',
                    'Could not save the two-factor data. Check that plugins/2fa/data is writable.'
                );
            }
        }
    }

    // Backup codes from the setup that just finished, shown once.
    if (empty($newCodes) && !empty($_SESSION['twofa_new_codes']) && is_array($_SESSION['twofa_new_codes'])) {
        $newCodes = $_SESSION['twofa_new_codes'];
        unset($_SESSION['twofa_new_codes']);
        $message = twofa_tx(
            'admin_enroll_done',
            'Two-factor authentication is now active. From now on, admin logins need a code after the password.'
        );
    }

    $out = '<div class="twofa-admin">';
    $out .= '<h1>' . XH_hsc(twofa_tx('admin_title', 'Two-Factor Authentication (2FA)')) . '</h1>';

    global $pth;
    $basePlugins = isset($pth['folder']['plugins']) ? $pth['folder']['plugins'] : './plugins/';
    $out .= '<p><a href="' . XH_hsc($basePlugins . '2fa/help/help.htm') . '" target="_blank" rel="noopener">'
        . XH_hsc(twofa_tx('admin_help_link', 'Help for this plugin (opens in a new window)')) . '</a></p>';

    if ($error !== '') {
        $out .= '<p class="xh_fail"><b>' . XH_hsc($error) . '</b></p>';
    }
    if ($message !== '') {
        $out .= '<p class="xh_success"><b>' . XH_hsc($message) . '</b></p>';
    }

    if (!empty($newCodes)) {
        $out .= '<div class="xh_warning" style="padding:1em;margin:1em 0;">';
        $out .= '<p><b>' . XH_hsc(twofa_tx(
            'admin_save_codes_now',
            'Save these new backup codes now. They will not be shown again:'
        )) . '</b></p>';
        $out .= '<ol>';
        foreach ($newCodes as $code) {
            $out .= '<li><code style="font-size:1.1em;">' . XH_hsc((string) $code) . '</code></li>';
        }
        $out .= '</ol>';
        $out .= '</div>';
    }

    $out .= twofa_access_html($check, $actionUrl, $csrfField);

    if (!$hasSecret) {
        // Setup: the first admin to reach this page sets the key, so do it right after installing.
        if (empty($_SESSION['twofa_pending'])) {
            $_SESSION['twofa_pending'] = twofa_new_secret();
        }
        $pending = (string) $_SESSION['twofa_pending'];

        $out .= '<p><b>' . XH_hsc(twofa_tx(
            'admin_status_setup',
            'Status: Not set up yet. Complete the steps below to turn on two-factor authentication.'
        )) . '</b></p>';
        $out .= '<h2>' . XH_hsc(twofa_tx('admin_enroll_heading', 'Set up Google Authenticator')) . '</h2>';
        $out .= '<p>' . XH_hsc(twofa_tx(
            'enroll_scan',
            'Scan this QR code with Google Authenticator (tap + and choose "Scan a QR code").'
        )) . '</p>';
        $out .= '<div id="twofa-qr" style="width:220px;height:220px"></div>';
        $out .= '<p>' . XH_hsc(twofa_tx(
            'enroll_manual',
            'Cannot scan? Choose "Enter a setup key" and type:'
        )) . ' <code style="font-size:1.1em">' . XH_hsc(trim(chunk_split($pending, 4, ' '))) . '</code></p>';
        $out .= '<form method="post" action="' . $actionUrl . '">';
        $out .= $csrfField;
        $out .= '<input type="hidden" name="twofa_admin_action" value="enroll">';
        $out .= '<p><label>' . XH_hsc(twofa_tx(
            'enroll_finish',
            'Then enter the 6-digit code it shows to finish.'
        )) . ' <input type="text" name="twofa_confirm_code" inputmode="numeric" autocomplete="one-time-code" '
            . 'pattern="[0-9 ]{6,7}" maxlength="7" required size="10"></label> '
            . '<button type="submit">' . XH_hsc(twofa_tx('admin_btn_enroll', 'Complete setup')) . '</button></p>';
        $out .= '</form>';
        $out .= twofa_qr_tags(twofa_otpauth($pending));
        $out .= '</div>';

        return $out;
    }

    $out .= '<p>' . XH_hsc(twofa_tx('admin_status_active', 'Status: Active (Google Authenticator / TOTP)')) . '</p>';
    $remainingLabel = str_replace(
        '{count}',
        (string) (int) $remaining,
        twofa_tx('admin_backup_remaining', 'Remaining one-time backup codes: {count} of 10')
    );
    $out .= '<p><b>' . XH_hsc($remainingLabel) . '</b></p>';

    if ($remaining <= 3) {
        $out .= '<p class="xh_warning">' . XH_hsc(twofa_tx(
            'admin_backup_low',
            'You are running low on backup codes. Consider generating a fresh set below.'
        )) . '</p>';
    }

    $out .= '<hr>';
    $out .= '<h2>' . XH_hsc(twofa_tx('admin_regen_heading', 'Regenerate Backup Codes')) . '</h2>';
    $out .= '<p>' . XH_hsc(twofa_tx(
        'admin_regen_desc',
        'Generating a new set of 10 backup codes immediately invalidates any unused codes from your previous set. Enter a current 6-digit code from Google Authenticator to confirm.'
    )) . '</p>';
    $out .= '<form method="post" action="' . $actionUrl . '">';
    $out .= $csrfField;
    $out .= '<input type="hidden" name="twofa_admin_action" value="regenerate">';
    $out .= '<p><label>' . XH_hsc(twofa_tx('admin_label_auth_code', 'Authenticator code:')) . ' '
        . '<input type="text" name="twofa_confirm_code" inputmode="numeric" autocomplete="one-time-code" '
        . 'pattern="[0-9 ]{6,7}" maxlength="7" required size="10"></label> '
        . '<button type="submit">' . XH_hsc(twofa_tx('admin_btn_regen', 'Generate New Backup Codes')) . '</button></p>';
    $out .= '</form>';

    $out .= '<hr>';
    $out .= '<h2>' . XH_hsc(twofa_tx('admin_reset_heading', 'Reset 2FA Secret')) . '</h2>';
    $out .= '<p>' . XH_hsc(twofa_tx(
        'admin_reset_desc',
        'Use this option if you are switching to a new phone and want to generate a brand-new secret key and QR code. Your current Google Authenticator entry and all existing backup codes will stop working immediately, and you will be redirected to the setup screen to scan the new QR code.'
    )) . '</p>';
    $confirmJs = json_encode(twofa_tx(
        'admin_reset_confirm',
        'Reset 2FA secret now? Your current authenticator entry and backup codes will stop working immediately.'
    ));
    $out .= '<form method="post" action="' . $actionUrl . '" '
        . 'onsubmit="return confirm(' . XH_hsc((string) $confirmJs) . ');">';
    $out .= $csrfField;
    $out .= '<input type="hidden" name="twofa_admin_action" value="reset">';
    $out .= '<p><label>' . XH_hsc(twofa_tx('admin_label_reset_code', 'Current authenticator or backup code:')) . ' '
        . '<input type="text" name="twofa_confirm_code" autocomplete="one-time-code" '
        . 'maxlength="11" required size="12"></label> '
        . '<button type="submit">' . XH_hsc(twofa_tx('admin_btn_reset', 'Reset 2FA Secret')) . '</button></p>';
    $out .= '</form>';

    $out .= '</div>';

    return $out;
}
