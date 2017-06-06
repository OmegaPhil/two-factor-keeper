General
=======

Two Factor Keeper is a basic PyQt5 GUI wrapper around the [oathtool commandline
program](http://www.nongnu.org/oath-toolkit/oathtool.1.html), and allows the
user quick access to any number of oath/2FA/2 Factor Authentication credentials,
of which the keys/secrets are protected by the [3rd party Python cryptography package Fernet
implementation](https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet),
specific implementation details [here](https://cryptography.io/en/latest/fernet/#implementation).

This is my first PyQt5/Qt Designer project.

**Note that neither this program nor the cryptography library used have been
audited by a cryptography expert, so they are only assumed to be secure.** Use
at your own risk, unfortunately (security limitations with this library are
touched on [here](https://cryptography.io/en/latest/limitations/)).

**I currently only have TOTP sites in use with this, so HOTP is untested but
should work fine as oathtool is the thing doing the real work. Please report
your success with HOTP!**


Dependencies
============

Coded with/dependent on (may work with earlier versions):

Python 3.5  
PyQt5 5.7  
python3-cryptography 1.7.1  
python3-yaml 3.12  
oathtool 2.6.1

All 3rd party dependencies are available packaged in Debian/Devuan.


Installation
============

As of yet there is no need to install this script, as long as the dependencies
are satisfied and the 'ui_mainwindow.py' script accompanies
'two-factor-keeper.py' - you can run the latter anywhere.


Usage
=====

Create Your First Slot
----------------------

On the first run of Two Factor Keeper, you'll be met with a mostly blank
interface:

TODO: first-run-ui

2FA configuration/credentials are collected into 'slots', and the left empty
list indicates there are no slots configured yet.

On the right, type a name that you will remember to identify the credentials
(e.g. site name), then enter the key/secret that the service/site has given you.
Usually this is a base32 encoded string (just a long string of capital letters
and numbers potentially with one or more '=' at the end) - this option is on
by default.

Type/paste the secret (make sure there are no empty lines or spaces at the end),
then encrypt it - press the top-right lock button (currently in the unlocked
state), and enter your passphrase:

TODO: encrypt-otp-secret

Once a valid passphrase has been accepted, the key/secret widget locks, and the
encryption button has now changed to a locked decryption button:

TODO: otp-secret-encrypted

Under 'Mode and basic options', choose TOTP (Time-based One Time Password)
rather than HOTP (Hash-based One Time Password) if the site you're configuring
for uses Google-style 2FA. If this is the case, all other options will work
with the defaults (SHA1 TOTP algorithm etc).

For sites that support it, you can configure more secure OTP generation with
more advanced hashes resulting in a number up to 8 digits long (the current
oathtool limit).


Generating A One Time Password
------------------------------

Once you are happy with the configuration, to create the first slot you can use
either the Apply or Add buttons at the bottom.

To generate the OTP, press the 'Generate OTP' button on the bottom left -
you'll be prompted for the passphrase:

TODO: generate-otp-secret-passphrase-prompt

Get it right, and your OTP code is ready:

TODO: otp-generated

This code is usually valid for 30 seconds after the site first asks for it, and
for your convenience it has also been copied to the clipboard.


Further Configuration
---------------------

To change the key/secret, press the locked button and enter the passphrase - if
you no longer remember the passphrase, and don't mind losing the secret, press
the brush button to the right of the lock to erase:

TODO: erase-otp-secret

If you make a change to a slot, haven't saved yet and want to undo it, use the
Reset button at the bottom to load the previously-saved configuration.

To remove a slot, select it in the list then use the Remove button on the bottom
right.


Bugs And Feature Requests
=========================

Please create an issue on the Github issue tracker.


Contact Details
===============

OmegaPhil: OmegaPhil@startmail.com
