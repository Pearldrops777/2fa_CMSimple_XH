# 2fa — Two-Factor Login (Google Authenticator) for CMSimple_XH

After a correct CMSimple_XH admin password, the site asks for a 6-digit code from Google Authenticator before any admin page or action runs. Setup is done in the backend under **Plugins -> 2fa**.

## What It Does

- **Setup in the backend:** Open **Plugins -> 2fa** to set up two-factor authentication. The page shows a QR code and a setup key. Scan the code in Google Authenticator (or type the key), then enter the 6-digit code to finish. Ten one-time backup codes are shown once right after setup.
- **Before setup is complete:** A password login goes straight to **Plugins -> 2fa** without a code prompt, so that page can be reached with the admin password alone. See [Installation and setup](#installation-and-setup).
- **After setup:** Every admin login asks for a fresh 6-digit code after the password.
- **Replay and brute-force protection:** Each code can be used only once. Five wrong codes across the login prompt or the backend forms lock verification for 15 minutes.
- **One-time backup codes:** Each backup code works once in place of the app code, for example if you lose your phone. A used code is removed immediately. Only the hashes of the codes are stored on the server.
- **Backend management (`Plugins -> 2fa`):** View the remaining backup code count, generate a fresh set of 10 backup codes, or reset the 2FA secret.
- **Access protection check (`Plugins -> Check for Access Protection`):** Checks the whole plugin folder for files that other users can write to, and tests whether `data/`, `data/twofa.php` are blocked from web access. It also reports file permissions and whether PHP can write to `data/`.
- **Multi-language support:** Includes built-in English (`en`), Dutch (`nl`), and German (`de`) language files editable via **Plugins -> 2fa -> Language**. The language files include the setup strings added in version 1.0.6.
- **Transparent to visitors:** Visitors who are not logged in see no change.

The plugin does not modify any CMSimple_XH core files, so CMSimple_XH updates will not remove it.

## Requirements

- **CMSimple_XH 1.8** (written against the 1.8 core files; test on a staging copy before deploying to a live site)
- **PHP 7.1 or newer** with the `hash_hmac`, `random_bytes`, and `intdiv` functions enabled
- **Apache** with `mod_authz_core` (or the older `Order`/`Deny` rules, which are included as a fallback). If you run Nginx, see `addendum.txt`.
- A phone with **Google Authenticator** (or another RFC 6238 TOTP app such as Aegis, FreeOTP, or Microsoft Authenticator)

## Folder Layout

The plugin folder must be named exactly `2fa`. The name starts with a digit on purpose: CMSimple_XH loads plugins in alphabetical order, so this plugin loads before other plugins.

```text
plugins/
  2fa/
    index.php                              # Login gate and code check (required)
    admin.php                              # Backend panel under Plugins -> 2fa: setup, backup codes, reset (required)
    version.nfo                            # CMSimple_XH update checker metadata
    LICENSE                                # GNU General Public License v3
    README.md                              # Documentation (optional)
    addendum.txt                           # File permission and Nginx notes, for servers that need them (optional)
    help/
      help.htm                             # Standalone help page (optional)
    languages/
      en.php                               # English language strings
      nl.php                               # Dutch language strings
      de.php                               # German language strings
    js/
      qrcode.js                            # QR code library, MIT license (required)
      QRCODE-GENERATOR-LICENSE-README.md   # License notice (keep it)
    data/                                  # Created/populated by the server on first use
      .htaccess                            # Blocks direct web access on Apache (required)
      index.php                            # Blocks directory indexing on Nginx/Caddy
      (twofa.php)                          # TOTP secret, backup code hashes & rate-limit state
                                           # (created automatically by setup; never publish or copy it)
```

## Installation and setup

Do this right after installing. Until setup is complete, the admin password alone reaches the backend.

1. Unzip the downloaded 2fa.zip and copy the 2fa folder into your CMSimple_XH `plugins/` directory. The folder name must be exactly `2fa`. Do not copy it to an Apache reverse proxy. The plugin must run on the server that runs CMSimple_XH's PHP.
2. Log in to CMSimple_XH with your admin password. Because setup is not finished, no code is asked.
3. Go to **Plugins -> 2fa**. The page shows **Status: Not set up yet** and the setup section.
4. Scan the QR code with Google Authenticator (tap **+** and choose **Scan a QR code**), or choose **Enter a setup key** and type the key shown below the code.
5. Enter the 6-digit code the app shows and click **Complete setup**. Setup is not finished until this code is accepted.
6. Save the 10 backup codes shown on the same page. They are displayed once. Print them or write them down.
7. Test the setup:
   - Log out and log in again: the 2FA code prompt must appear.
   - A wrong code must be refused.
   - The same code must not work twice.
   - Optional: verify that a backup code logs you in once and is then invalidated.

> **Important:** Until step 5 is complete, anyone who knows the admin password can complete the setup and set the key. Do the setup right after installing, and use a strong, unique admin password.

If the setup key expires (for example, after a long pause), reload **Plugins -> 2fa** and scan the new QR code.

## Managing & Resetting 2FA

### Moving to a New Phone (Without Resetting)
Google Authenticator supports account transfers (**Menu -> Transfer accounts -> Export accounts**). Scan the transfer QR code with your new phone to copy your existing entry without changing anything on the website.

### Regenerating Backup Codes or Resetting via Backend
1. Log in to CMSimple_XH and go to **Plugins -> 2fa**. Enter a 6-digit code when the code prompt appears.
2. To replace your backup codes, enter a current 6-digit authenticator code under **Regenerate Backup Codes**. Old backup codes stop working immediately.
3. To pair a new device with a brand-new secret key, enter a current 6-digit code (or an unused backup code) under **Reset 2FA Secret**. The secret and all backup codes are removed, and you are sent back to **Plugins -> 2fa** to set up again with the steps in [Installation and setup](#installation-and-setup). *(To use multiple devices, scan the same QR code on each device before completing setup.)*

### Checking Access Protection
1. Go to **Plugins -> Check for Access Protection**. This opens the 2fa page and runs the check.
2. Read the results. A check mark means the item is OK. A cross means it needs fixing. A question mark means the check could not be run from the server.
3. Fix any problems using `addendum.txt`, then select **Run check** to test again.

The web-access tests only work on a live site. Run them on the site itself, not on a local copy.

## Troubleshooting

- **"Could not save the two-factor data. Check that plugins/2fa/data is writable."**
  The code was accepted, but PHP could not write `data/twofa.php`. This only happens on servers with strict file permissions. See `addendum.txt` for the fix, and check your web server error log (`/var/log/apache2/error.log` or `/var/log/httpd/error_log`).
- **"The setup key has expired"**
  Reload **Plugins -> 2fa**. A new QR code and setup key are created.
- **Cannot save changes in Plugins -> 2fa -> Language**
  This only happens on servers with strict file permissions. See `addendum.txt`.
- **The QR code area is empty or shows "QR code not shown"**
  `js/qrcode.js` is missing or blocked by web server rules. Re-upload the `js/` folder. The setup key below the QR code still works.
- **"Too many failed attempts"**
  Five wrong codes locked verification for 15 minutes. Wait 15 minutes and try again with a fresh code.
- **The code is always refused**
  Ensure your phone's clock is set to automatic network time synchronization. TOTP depends on accurate UTC time.
- **A backup code is refused**
  Each backup code works only once. Check that it has not been used previously (dashes and letter case are ignored). Failed backup code attempts count toward the same 5-attempt lockout.
- **Locked out completely (lost phone, wrong key, and lost backup codes)**
  Connect via FTP, SFTP, or SSH and delete:
  ```text
  /var/www/html/plugins/2fa/data/twofa.php
  ```
  The next password login goes to **Plugins -> 2fa**, where setup starts again with a fresh QR code. Have your phone ready before deleting the file, and complete setup right away, because until then the admin password alone reaches the backend.
- **Login succeeds without a code prompt**
  Setup is not complete yet. Finish it under **Plugins -> 2fa**. Also ensure the folder is named exactly `plugins/2fa/` and that `2fa` is not listed under `plugins/disabled` in CMSimple_XH's configuration.

## Security Notes

- Keep the `data/` folder private. Anyone who can read `data/twofa.php` can generate valid login codes.
- Never publish, copy, or screenshot `data/twofa.php`, your setup key, or your backup codes.
- Until setup is complete, the admin password alone reaches **Plugins -> 2fa**. Complete setup right after installing.
- This plugin protects the admin login flow; it does not protect against an attacker who already has filesystem or server access.
- Page-data saves run in the CMSimple_XH core before plugins load, so an attacker with only the admin password could still save page data before the 2FA prompt once setup is complete. Always use a strong, unique admin password.
- Test on a copy of your site before deploying to production.

## License

- The plugin code (`index.php`, `admin.php`) is licensed under the **GNU General Public License v3 (GPLv3)** — see the `LICENSE` file for details.
- `js/qrcode.js` is **qrcode-generator 1.5.2** by Kazuhiko Arase, licensed under the MIT License (see the file header and `js/QRCODE-GENERATOR-LICENSE-README.md`).

## Changelog

### 1.0.7
- Added **Check for Access Protection** to the Plugins menu. It checks the whole plugin folder for files that other users can write to, tests web access to the plugin folder (no directory listing), `data/`, and `data/twofa.php`, and reports file permissions and whether PHP can write to `data/`.
- The check runs on the **Plugins -> 2fa** page, which also has a **Run check** button.

### 1.0.6
- Setup (QR code, setup key, first code, and backup codes) moved from the login screen to the backend (`admin.php`, **Plugins -> 2fa**).
- Until setup is complete, a password login goes straight to the backend without a code prompt.
- Once setup is complete, the code prompt works as before on every admin login.
- Reset now returns to the backend setup page instead of the login screen.
- File permission instructions moved from this file to `addendum.txt`.
- The English, Dutch, and German language files are updated for the backend setup, the help link, and the reset changes.

### 1.0.5
- Added multi-language support (`languages/en.php`, `languages/nl.php`, `languages/de.php`) editable via **Plugins -> 2fa -> Language**.
- Shared the 5-attempt / 15-minute brute-force lockout across both the login challenge and the backend confirmation forms (`admin.php`).
- Loaded `js/qrcode.js` via an external `<script src="...">` tag instead of inline script injection for browser caching and strict CSP compatibility.
- Added `data/index.php` directory-listing guard and root `LICENSE` (GPLv3) file.

### 1.0.4
- Added backend administration panel (`admin.php`) under **Plugins -> 2fa** to view remaining backup code count, regenerate backup codes, and reset the 2FA secret.
- Added `version.nfo` for CMSimple_XH update checking.

### 1.0.3
- Added proper logout handling directly from the 2FA verification screen.
- Regenerated session ID upon successful 2FA verification and logout to prevent session fixation.
- Sanitized redirect URIs (`twofa_safe_uri()`) to prevent open redirects.
- Added a short delay on failed code attempts to further slow down brute-force attacks.

### 1.0.2
- Added 10 one-time backup codes generated during initial 2FA setup.

### 1.0.1
- Updated installation instructions to include `sudo` for setting directory and file permissions.

### 1.0.0
- Initial release with TOTP (Google Authenticator) support and client-side QR code generation.
