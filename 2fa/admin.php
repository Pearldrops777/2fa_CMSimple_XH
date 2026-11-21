<?php
/**
 * CMSimple_XH plugin "2fa": Backend administration panel.
 *
 * Accessible via Plugins -> 2fa in the CMSimple_XH admin menu.
 * Allows viewing remaining backup code count, regenerating 10 new
 * one-time backup codes, resetting the TOTP secret, and editing
 * language strings via CMSimple_XH's standard plugin language editor.
 */

if (!defined('CMSIMPLE_XH_VERSION')) {
    return;
}

global $admin, $action, $plugin, $o;

XH_registerStandardPluginMenuItems(false);

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
 * Renders the 2FA status, backup-code regeneration, and secret-reset form.
 */
function twofa_admin_view(): string
{
    global $_XH_csrfProtection;

    $data = twofa_load();
    $hasSecret = !empty($data['secret']);
    $remaining = isset($data['backup_hashes']) && is_array($data['backup_hashes'])
        ? count($data['backup_hashes'])
        : 0;

    $message = '';
    $error = '';
    $newCodes = [];

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['twofa_admin_action'])) {
        if (isset($_XH_csrfProtection) && is_object($_XH_csrfProtection)) {
            $_XH_csrfProtection->check();
        }

        $act = (string) $_POST['twofa_admin_action'];

        if (!$hasSecret) {
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
                $data['last_step'] = $step;
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

    $actionUrl = XH_hsc(twofa_safe_uri());
    $csrfField = (isset($_XH_csrfProtection) && is_object($_XH_csrfProtection))
        ? $_XH_csrfProtection->tokenInput()
        : '';

    $out = '<div class="twofa-admin">';
    $out .= '<h1>' . XH_hsc(twofa_tx('admin_title', 'Two-Factor Authentication (2FA)')) . '</h1>';

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
            $out .= '<li><code style="font-size:1.1em;">' . XH_hsc($code) . '</code></li>';
        }
        $out .= '</ol>';
        $out .= '</div>';
    }

    if (!$hasSecret) {
        $out .= '<p>' . XH_hsc(twofa_tx(
            'admin_status_inactive',
            'Status: Not configured. Log out and log back in to complete enrollment.'
        )) . '</p>';
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
        'Use this option if you are switching to a new phone and want to generate a brand-new secret key and QR code. Your current Google Authenticator entry and all existing backup codes will stop working immediately, and you will be redirected to the enrollment screen to scan the new QR code.'
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
