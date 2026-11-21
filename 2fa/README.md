# 2fa — Two-Factor Login (Google Authenticator) for CMSimple_XH

After a correct CMSimple_XH admin password, the site asks for a 6-digit code from Google Authenticator before any admin page or action runs.

## What It Does

- **First login after installation:** A QR code and a setup key are shown. Scan the code in Google Authenticator (or type the key), then enter the 6-digit code to finish setup.
- **Every subsequent login:** Password login always requires a fresh 6-digit code.
- **Shared replay & brute-force protection:** Codes can be used only once. Five wrong codes across either the login prompt or the backend panel lock verification for 15 minutes.
- **One-time backup codes:** When setup finishes, 10 one-time backup codes are shown once. Save them (print them or write them down). Each code works once in place of the app code—for example, if you lose your phone. A used code is immediately removed. Only the hashes of the codes are stored on the server.
- **Backend management (`Plugins -> 2fa`):** View the remaining backup code count, generate a fresh set of 10 backup codes, or reset the 2FA secret key directly from the CMSimple_XH admin panel.
- **Multi-language support:** Includes built-in English (`en`), Dutch (`nl`), and German (`de`) language files editable via **Plugins -> 2fa -> Language**.
- **Transparent to visitors:** Visitors who are not logged in see no change.

The plugin does not modify any CMSimple_XH core files, so CMSimple_XH updates will not remove it.

## Requirements

- **CMSimple_XH 1.8** (written against the 1.8 core files; test on a staging copy before deploying to a live site)
- **PHP 7.1 or newer** with the `hash_hmac`, `random_bytes`, and `intdiv` functions enabled
- **Apache** with `mod_authz_core` (or the older `Order`/`Deny` rules, which are included as a fallback). Nginx ignores `.htaccess` files—see the [Nginx](#nginx) section below.
- A phone with **Google Authenticator** (or another RFC 6238 TOTP app such as Aegis, FreeOTP, or Microsoft Authenticator)

## Folder Layout

The plugin folder must be named exactly `2fa`. The name starts with a digit on purpose: CMSimple_XH loads plugins in alphabetical order, so this plugin loads before other plugins.

```text
plugins/
  2fa/
    index.php                              # Login gate, TOTP & backup code verification (required)
    admin.php                              # Backend panel under Plugins -> 2fa (required)
    version.nfo                            # CMSimple_XH update checker metadata
    LICENSE                                # GNU General Public License v3
    README.md                              # Documentation (optional)
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
      twofa.php                            # TOTP secret, backup code hashes & rate-limit state
                                           # (created automatically; never publish or copy it)
```

## Installation

1. Download and unzip `2fa.zip`. Copy the `2fa` folder into your CMSimple_XH `plugins/` directory so you have:
   - `plugins/2fa/index.php`
   - `plugins/2fa/admin.php`
   - `plugins/2fa/version.nfo`
   - `plugins/2fa/LICENSE`
   - `plugins/2fa/languages/en.php`, `nl.php`, and `de.php`
   - `plugins/2fa/js/qrcode.js` and `QRCODE-GENERATOR-LICENSE-README.md`
   - `plugins/2fa/data/.htaccess` and `plugins/2fa/data/index.php`
   *(Do not copy it to an Apache reverse proxy if your site uses one. The plugin must run on the server executing CMSimple_XH PHP.)*
2. Set the proper file ownership and permissions (see [Permissions](#permissions) below).
3. Log in to CMSimple_XH with your admin password. The setup screen appears. Scan the QR code with Google Authenticator and enter the 6-digit code.
4. Save the 10 one-time backup codes displayed on the following screen.
5. **Test the setup:**
   - Log out and log in again: the 2FA code prompt must appear.
   - A wrong code must be refused.
   - The same code must not work twice.
   - Optional: verify that a backup code logs you in once and is then invalidated.

> **Important:** Complete the first setup immediately after installing. Whoever logs in with the admin password first sets the 2FA key.

## Permissions

Replace `www-data` with the user that runs PHP on your server if different (check via `phpinfo()` or the owner of existing CMSimple_XH folders), and adjust `/var/www/html/plugins` if your installation path differs.

| Item | Owner | Mode |
| :--- | :--- | :--- |
| `plugins/2fa/` | deploy user or `www-data` | `755` |
| `plugins/2fa/*.php`, `version.nfo`, `LICENSE`, `README.md` | deploy user or `www-data` | `644` |
| `plugins/2fa/js/` | deploy user or `www-data` | `755` |
| `plugins/2fa/js/qrcode.js` | deploy user or `www-data` | `644` |
| `plugins/2fa/languages/` | `www-data` | `755` |
| `plugins/2fa/languages/*.php` | `www-data` | `644` |
| `plugins/2fa/data/` | `www-data` | `700` |
| `plugins/2fa/data/.htaccess`, `plugins/2fa/data/index.php` | `www-data` | `644` |
| `plugins/2fa/data/twofa.php` *(created by PHP)* | `www-data` | `600` |

Run as `root` or with `sudo`:

```bash
cd /var/www/html/plugins
sudo chown -R www-data:www-data 2fa
sudo find 2fa -type d -exec chmod 755 {} +
sudo find 2fa -type f -exec chmod 644 {} +

# Make languages/ and its files writable by www-data for the built-in language editor:
sudo chown -R www-data:www-data 2fa/languages
sudo chmod 755 2fa/languages
sudo chmod 644 2fa/languages/*.php

# Lock down data/ so only www-data can read or write the secret:
sudo chown -R www-data:www-data 2fa/data
sudo chmod 700 2fa/data

# After the first successful setup:
sudo chmod 600 2fa/data/twofa.php
```

**Why:** PHP must be able to write to `data/` to save the secret and rate-limit state, and to `languages/` if you edit translations via **Plugins -> 2fa -> Language**. Nothing outside `data/` and `languages/` requires write access by `www-data`. Never use `777`.

## Managing & Resetting 2FA

### Moving to a New Phone (Without Resetting)
Google Authenticator supports account transfers (**Menu -> Transfer accounts -> Export accounts**). Scan the transfer QR code with your new phone to copy your existing entry without changing anything on the website.

### Regenerating Backup Codes or Resetting via Backend
1. Log in to CMSimple_XH and go to **Plugins -> 2fa**.
2. To replace your backup codes, enter a current 6-digit authenticator code under **Regenerate Backup Codes**.
3. To pair a new device with a brand-new secret key, enter a current 6-digit code (or unused backup code) under **Reset 2FA Secret**. You will be immediately redirected to the setup screen to scan the new QR code and save 10 new backup codes. *(To use multiple devices, scan the same QR code on each device before confirming.)*

## Troubleshooting

- **"Could not save the two-factor data. Check that plugins/2fa/data is writable."**
  The code was accepted, but PHP could not write `data/twofa.php`. Verify the owner and permissions of `plugins/2fa/data` (see [Permissions](#permissions)) and check your web server error log (`/var/log/apache2/error.log` or `/var/log/httpd/error_log`).
- **Cannot save changes in Plugins -> 2fa -> Language**
  Ensure `/var/www/html/plugins/2fa/languages` and the `.php` files inside it are owned by `www-data:www-data` with modes `755` and `644`.
- **The QR code area is empty or shows "QR code not shown"**
  `js/qrcode.js` is missing, unreadable by the web-server user, or blocked by web server rules. Re-upload the `js/` folder and verify its `644` file permissions.
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
  The next password login will restart setup with a fresh QR code and 10 new backup codes. Have your phone ready before deleting the file.
- **Nothing happens; login succeeds without a code prompt**
  Ensure the folder is named exactly `plugins/2fa/` and that `2fa` is not listed under `plugins/disabled` in CMSimple_XH's configuration.

## Nginx

Nginx ignores `.htaccess` files. If your server runs Nginx, block web access to the `data/` directory in your server block:

```nginx
location ^~ /plugins/2fa/data/ {
    deny all;
}
```

## Security Notes

- Keep the `data/` folder private. Anyone who can read `data/twofa.php` can generate valid login codes.
- Never publish, copy, or screenshot `data/twofa.php`, your setup key, or your backup codes.
- This plugin protects the admin login flow; it does not protect against an attacker who already has filesystem or server access.
- Page-data saves run in the CMSimple_XH core before plugins load, so an attacker with only the admin password could still save page data prior to the 2FA prompt. Always use a strong, unique admin password.
- Test on a copy of your site before deploying to production.

## License

- The plugin code (`index.php`, `admin.php`) is licensed under the **GNU General Public License v3 (GPLv3)** — see the `LICENSE` file for details.
- `js/qrcode.js` is **qrcode-generator 1.5.2** by Kazuhiko Arase, licensed under the MIT License (see the file header and `js/QRCODE-GENERATOR-LICENSE-README.md`).

## Changelog

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
