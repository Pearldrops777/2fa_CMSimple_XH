2fa - Two-factor login (Google Authenticator) for CMSimple_XH
=============================================================

WHAT IT DOES
------------
After a correct CMSimple_XH admin password, the site asks for a 6-digit
code from Google Authenticator before any admin page or action runs.

- First login after installation: a QR code and a setup key are shown.
  Scan the code in Google Authenticator (or type the key), then enter the
  6-digit code to finish setup.
- Every later password login asks for a fresh code.
- Codes can be used only once. Five wrong codes lock the prompt for
  15 minutes.
- Backup codes: when setup finishes, 10 one-time backup codes are shown
  once. Save them (print them or write them down). Each code works once
  in place of the app code, for example if you lose your phone. A used
  code is removed. Only the hashes of the codes are stored on the server.
  The codes are not shown again, so if you lose them, delete
  data/twofa.php and set up again (see TROUBLESHOOTING).
- Visitors who are not logged in see no change.

The plugin does not change any CMSimple_XH core file, so CMSimple_XH
updates do not remove it.


REQUIREMENTS
------------
- CMSimple_XH 1.8 (written against the 1.8 core files; not yet tested
  on a live site)
- PHP with the hash_hmac, random_bytes and intdiv functions (PHP 7.1 or newer)
- Apache with mod_authz_core (or the older Order/Deny rules, which are
  included as fallback). Nginx ignores .htaccess files, see "Nginx" below.
- A phone with Google Authenticator (or another TOTP app such as
  Aegis, FreeOTP or Microsoft Authenticator)


FOLDER LAYOUT
-------------
The plugin folder must be named exactly "2fa". The name starts with a
digit on purpose: CMSimple_XH loads plugins in alphabetical order, so
this plugin loads before the others.

  plugins/
    2fa/
      index.php              the plugin (required)
      README.txt             this file (optional, can be removed)
      js/
        qrcode.js            QR code library, MIT license (required)
        QRCODE-GENERATOR-LICENSE-README.md   license notice (keep it)
      data/                  created by the server on first use
        .htaccess            blocks web access (required)
        twofa.php            TOTP secret, backup code hashes and rate-limit
                             data (created automatically; never publish or
                             copy it)


INSTALLATION
------------
1. Download and unzip 2fa.zip. Copy the "2fa" folder to the CMSimple_XH backend's
   plugins/ folder, so that you have the following file and directory structure:
       plugins/2fa/index.php
       plugins/2fa/js/qrcode.js and QRCODE-GENERATOR-LICENSE-README.md
       plugins/2fa/data/.htaccess
   Do not copy it to the Apache reverse proxy if the site uses one. The
   plugin must run on the server that runs CMSimple_XH (PHP).

2. Then give them the right owner and permissions (see PERMISSIONS below).

3. Log in to CMSimple_XH with the admin password. The setup screen
   appears. Scan the QR code with Google Authenticator, then enter the
   6-digit code. The login completes after a correct code. Then save the
   10 backup codes that appear on the next screen.

4. Test the setup:
   - log out and log in again: the code prompt must appear
   - a wrong code must be refused
   - the same code must not work twice
   - optional: check that a backup code logs you in once and is then refused

Do the first setup right after installing. Whoever logs in with the
password first sets the key.


PERMISSIONS
-----------
Replace "www-data" with the user that runs PHP on your server if it is
different (check with a phpinfo page, or with the owner of other
CMSimple_XH folders). Replace /path/to with your installation path.

  Item                                   Owner                 Mode
  -------------------------------------  --------------------  ------
  plugins/2fa/                           the deploy user or    755
                                         www-data
  plugins/2fa/index.php                  the deploy user or    644
                                         www-data
  plugins/2fa/js/                        the deploy user or    755
  plugins/2fa/js/qrcode.js               the deploy user or    644
  plugins/2fa/data/                      www-data              700
  plugins/2fa/data/.htaccess             www-data              644
  plugins/2fa/data/twofa.php             www-data              600
                                         (created by PHP)

Commands (run as root or with sudo):

  cd /path/to/plugins
  sudo chown -R www-data:www-data 2fa
  sudo find 2fa -type d -exec chmod 755 {} +
  sudo find 2fa -type f -exec chmod 644 {} +
  sudo chown www-data:www-data 2fa/data
  sudo chmod 700 2fa/data
  # after the first successful setup:
  sudo chmod 600 2fa/data/twofa.php

Why: PHP must be able to write to data/ to save the secret. Nothing
outside data/ needs write access. The data folder is not readable by
other users, and twofa.php holds the secret. Do not use 777 (the
server's existing 777 settings are a separate risk; see the notes
below).


TROUBLESHOOTING
---------------
"Could not save the two-factor data. Check that plugins/2fa/data is
writable."
  The code was accepted, but PHP cannot write data/twofa.php.
  Check the owner and mode of plugins/2fa/data (see PERMISSIONS).
  Check the Apache error log (/var/log/apache2/error.log or
  /var/log/httpd/error_log) for a "Permission denied" line.

The QR code area is empty, or shows "QR code not shown".
  js/qrcode.js is missing or not readable by the web-server user.
  Copy the js folder again and check its permissions.

"Too many failed attempts"
  Five wrong codes locked the prompt for 15 minutes. Wait, then try
  again with the current code.

The code is always refused
  Check that the phone's clock is set automatically (time sync). Codes
  depend on the time, and a wrong clock causes refused codes.

A backup code is refused
  Each backup code works once. Check that you typed it correctly (dashes
  and capitals do not matter), and that it was not used before. Each
  attempt counts toward the same five-attempt lock as an app code.

Locked out for good (lost phone, wrong key, lost backup codes)
  Delete the secret file over FTP or SSH:
      plugins/2fa/data/twofa.php
  The next password login starts setup again, with a new key and new
  backup codes. Have the new phone ready before you delete the file.

Nothing happens, login works without a code
  The plugin folder is missing, is named differently, or is disabled.
  The folder must be exactly plugins/2fa/. Check that "2fa" is not in
  the "plugins/disabled" setting in CMSimple_XH's configuration.


NGINX
-----
Nginx ignores .htaccess files. If the server runs Nginx, block web
access to the data folder in the server configuration instead:

  location ^~ /plugins/2fa/data/ { deny all; }


SECURITY NOTES
--------------
- Keep the data folder private. Anyone who can read data/twofa.php can
  generate the login codes.
- Do not publish, copy or screenshot data/twofa.php, the setup key, or
  your backup codes.
- The plugin protects the admin login. It does not protect against
  someone who gets access to the server.
- Page-data saves run in the core before plugins load, so a person with
  only the password could save page data before the code prompt. Keep
  the admin password strong.
- Test on a copy of the site before you use it on the live site.


LICENSE
-------
The plugin code (index.php) is provided as is, without warranty. Add
your own license here if you distribute it.

js/qrcode.js is qrcode-generator 1.5.2 by Kazuhiko Arase, under the
MIT license. The license notice is in the file header and in
js/QRCODE-GENERATOR-LICENSE-README.md.
