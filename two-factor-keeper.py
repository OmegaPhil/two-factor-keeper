#!/usr/bin/env python3

'''GUI wrapper around oathtool that allows you to maintain multiple sets of two
factor authentication credentials'''


# Version 0.1 2017.06.06
# Copyright (c) 2017, OmegaPhil - OmegaPhil@startmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import base64
import enum
import io
import os
import os.path
import sys
import traceback

import yaml

# pylint:disable=global-statement,no-name-in-module,redefined-outer-name,
# pylint:disable=too-few-public-methods,too-many-arguments,too-many-statements

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt5.QtCore import Qt  # Contains enums
from PyQt5.QtGui import QGuiApplication, QIcon
from PyQt5.QtWidgets import QApplication, QDialog, QInputDialog
from PyQt5.QtWidgets import QLineEdit, QMainWindow, QMessageBox
from sh import oathtool

from ui_mainwindow import Ui_MainWindow


# Trusted source of the last loaded slot name, also used to avoid slot 'change
# detection' when the first slot is loaded
last_loaded_slot = None

# Hack to work around Qt's inability to prevent a list widget row change. Used
# when backing out a row/slot change in the UI, and preventing spurious change
# detection on adding a new slot based off an old one
ignore_slot_change = False

salt = None  # Temporary storage for salt prior to a slot being saved
SCRIPT_NAME = 'Two Factor Keeper'
slots_config = None


# Normal classes
class OTPSlot():
    '''Base OTP slot representation'''

    def __init__(self, name, key, base32_encoded, salt, digits):
        self.name = name
        self.key = key
        self.base32_encoded = base32_encoded
        self.salt = salt
        self.digits = digits


class HOTPSlot(OTPSlot):
    '''Hash-based OTP slot specialisation'''

    def __init__(self, name, key, base32_encoded, salt, digits, counter):

        # Intialising generic OTPSlot
        super().__init__(name, key, base32_encoded, salt, digits)

        # Type-specific config
        self.counter = counter


@enum.unique
class TOTPAlgorithm(enum.Enum):
    '''Acceptable algorithms to use with TOTP slots'''

    sha1 = 1
    sha256 = 2
    sha512 = 3


class TOTPSlot(OTPSlot):
    '''Time-based OTP slot specialisation'''

    def __init__(self, name, key, base32_encoded, salt, digits, totp_algorithm,
                 time_step_size, start_time, now_time):

        # Intialising generic OTPSlot
        super().__init__(name, key, base32_encoded, salt, digits)

        # Validation
        if not isinstance(totp_algorithm, TOTPAlgorithm):
            raise Exception('Attempt to instantiate TOTPSlot with an invalid '
                            'algorithm: \'%s\'\n\n%s'
                            % (totp_algorithm, traceback.format_exc()))

        # Type-specific config
        self.totp_algorithm = totp_algorithm
        self.time_step_size = time_step_size
        self.start_time = start_time
        self.now_time = now_time


# Exception hierarchy (only used where the complexity is needed)
class TwoFactorKeeperException(Exception):
    '''Base exception for custom exceptions'''
    pass


class SaveKeyNotEncryptedException(TwoFactorKeeperException):
    '''User has not locked the key/secret before saving'''
    pass


class SaveNameNotUniqueException(TwoFactorKeeperException):
    '''User has chosen a slot name that is already in use'''
    pass


def about():
    '''Show the about dialog'''

    text = '''Two Factor Keeper v0.1 Copyright (C) 2017 OmegaPhil (OmegaPhil@startmail.com)
    
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.'''
    QMessageBox.information(main_win, SCRIPT_NAME, text)


def clear_key():
    '''Clearing the key without a need for a password'''

    result = QMessageBox.question(main_win, SCRIPT_NAME, 'Are you sure you want'
                                  ' to erase the current key?')
    if result == QMessageBox.Yes:
        ui.key_plaintextedit.clear()
        ui.key_plaintextedit.setEnabled(True)
        ui.key_plaintextedit.setFocus()
        icon = QIcon.fromTheme('changes-allow')
        ui.encrypt_pushbutton.setIcon(icon)


def decrypt_key(encrypted_otp_key):
    '''Decryption that is requested via the UI lock button, or an attempt to
    generate a OTP'''

    # This is now an internal function, so remember that all failure modes must
    # raise an Exception rather than just returning

    # Obtaining a useful password
    password = prompt_for_password(False)
    if password == '':
        QMessageBox.warning(main_win, SCRIPT_NAME, 'Unable to decrypt the '
                            'key/secret with a blank password!')
        raise Exception

    # Generating fernet object (since we are decrypting we don't want to
    # generate new salt...)
    f = get_fernet(password, False)

    try:

        # Decrypting binary data and converting the result into a UTF-8 string
        decrypted_otp_key = f.decrypt(encrypted_otp_key.encode()).decode()

    except InvalidToken as e:

        # The known exception for decrypt is InvalidToken, however almost no
        # information is communicated by it - in the case of an invalid HMAC
        # signature, a little more information is available via exception
        # chaining, so giving the user a chance at a little more understanding
        QMessageBox.critical(main_win, SCRIPT_NAME, 'Decryption of the OTP key/'
                          'secret failed - the password used to decrypt the key '
                          'is wrong, or the key itself is corrupt. Please '
                          'confirm that the key ends with \'==\', otherwise try '
                          'a different password.\n\\nException from the crypto '
                          'library:\n\n%s'
                          % str(e.__context__))
        raise

    except Exception as e:

        # Unknown error occurred?
        QMessageBox.error(main_win, SCRIPT_NAME, 'Decryption of the OTP key/'
                          'secret failed - the error is different to the '
                          'password being wrong or the key corrupt, so is '
                          'probably a programming error:\n\n%s' % str(e))
        raise

    # Decryption succeeded
    return decrypted_otp_key


def decrypt_key_lock_button():
    '''Decryption triggered via the lock button in the UI'''

    # Making sure key is in a state to decrypt
    encrypted_otp_key = get_key_contents()
    if ui.key_plaintextedit.isEnabled() != False or encrypted_otp_key == '':
        raise Exception('decrypt_key_lock_button was called when the key '
                        'plaintextedit was enabled and/or has no contents!')

    try:

        # Obtaining decrypted key
        decrypted_otp_key = decrypt_key(encrypted_otp_key)

    # Exceptions are already dealt with in decrypt_key
    except Exception:  # pylint:disable=broad-except
        pass

    else:

        # Decryption succeeded, updating the UI
        ui.key_plaintextedit.setPlainText(decrypted_otp_key)
        ui.key_plaintextedit.setEnabled(True)
        ui.key_plaintextedit.setFocus()
        icon = QIcon.fromTheme('changes-allow')
        ui.encrypt_pushbutton.setIcon(icon)


def encrypt_key():
    '''Encrypt the key/secret and 'lock' the widget'''

    # Making sure an OTP key has been set
    otp_key = get_key_contents()
    if otp_key == '':
        QMessageBox.warning(main_win, SCRIPT_NAME, 'Please enter a key/secret '
                            'before attempting to encrypt it with this button!')
        ui.key_plaintextedit.setFocus()
        return

    # Obtaining a useful password
    password = prompt_for_password(True)
    if password == '':
        QMessageBox.warning(main_win, SCRIPT_NAME, 'Unable to encrypt the '
                            'key/secret with a blank password!')
        return

    # Process copied from https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
    # Getting binary representation of key
    otp_key = otp_key.encode()

    # Generating fernet object (salt is regenerated for every new encryption)
    f = get_fernet(password)

    # Encrypting and saving the otp_key - note that the widget naturally needs
    # a UTF-8 string and not bytes
    ui.key_plaintextedit.setPlainText(f.encrypt(otp_key).decode())
    ui.key_plaintextedit.setEnabled(False)
    icon = QIcon.fromTheme('changes-prevent')
    ui.encrypt_pushbutton.setIcon(icon)


def get_key_contents():
    '''Simple getter to ensure that any newlines are killed off when reading
    whatever is in the key widget'''

    # QLineEdit can't do any sort of wordwrapping, so for long hashes its
    # mostly outside the visible area of the widget. However any other widget
    # encourages more than one line... so as a compromise, this tries to purge
    # any newlines in order to treat the key as a single value on one line
    return ui.key_plaintextedit.toPlainText().replace('\n', '')


def get_fernet(password, refresh_salt=True):
    '''Obtain fernet object from raw password'''

    global salt

    # Converting to binary form to satisfy fernet
    password = password.encode()

    # Process copied from https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
    # Converting/stretching/strengthening key into format Fernet wants
    if refresh_salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=100000, backend=default_backend())
    fernet_key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(fernet_key)


def generate_otp():
    '''Generate One Time Password after possibly saving any slot changes'''

    global ignore_slot_change

    # Make sure an OTP slot exists/has been loaded before allowing for creation
    # of OTP
    if len(slots_config) == 0:
        QMessageBox.warning(main_win, SCRIPT_NAME, 'Please configure at least '
                            'one OTP slot before attempting to generate a One '
                            'Time Password!')
        return

    # Make sure any unsaved changes are accepted or rejected
    slot_name = ui.otp_list.currentItem().text()
    if has_slot_config_changed():
        result = QMessageBox.question(main_win, SCRIPT_NAME, "The \'%s\' OTP "
                                      "slot has unsaved changes - would you like"
                                      " to save these before generating the One"
                                      " Time Password? If not, the slot will be"
                                      " reset." % slot_name)
        if result == QMessageBox.Yes:

            # Attempting to save and bailing out on any exception
            try:

                # At this stage the currently-loaded slot having its name
                # changed is always a rename, not addition - so is_slot_new is
                # False
                save_slot(False)

            except TwoFactorKeeperException:
                return
        else:

            # Without ignoring the slot change, change detection code fires...
            ignore_slot_change = True
            otp_slot_reset()
            ignore_slot_change = False

    # Updating slot name after potential save of any changes above
    slot_name = ui.otp_list.currentItem().text()

    try:

        # Obtaining decrypted key (this also prompts the user for a password)
        decrypted_otp_key = decrypt_key(get_key_contents())

    # Exceptions are already dealt with in decrypt_key
    except Exception as e:  # pylint:disable=broad-except
        return

    # Collecting shared parameters
    parameters = ['--verbose', '--digits', slots_config[slot_name].digits]
    if slots_config[slot_name].base32_encoded:
        parameters.append('--base32')

    # Dealing with slot type parameters
    if ui.htop_radiobutton.isChecked():
        parameters.extend(['--counter', slots_config[slot_name].counter])
    else:
        parameters.append('--totp=' +
                          slots_config[slot_name].totp_algorithm.name)
        parameters.append('--time-step-size=' +
                          str(slots_config[slot_name].time_step_size) + 's')
        parameters.append('--start-time=' +
                          str(slots_config[slot_name].start_time))
        parameters.append('--now=' + str(slots_config[slot_name].now_time))

    parameters.append(decrypted_otp_key)

    try:
        result = oathtool(parameters).strip()

    except Exception as e:  # pylint:disable=broad-except

        text = ('Unable to generate the desired OTP - the oathtool call failed -'
                ' please see details below (note that the details may include '
                'the secret in plaintext):')
        dialog = QMessageBox(QMessageBox.Critical, SCRIPT_NAME, text,
                             parent=main_win)
        dialog.setInformativeText(str(e))
        dialog.exec_()
        return

    # Obtaining the generated OTP - last line
    otp = result.split('\n')[-1:][0]

    # Making sure the OTP is valid
    if not otp.isdigit():

        text = ('Unable to generate the desired OTP - the oathtool call '
                'succeeded but the output was not a number (called with the '
                'wrong parameters?) - please see details below (note that the '
                'details may include the secret in plaintext):')
        dialog = QMessageBox(QMessageBox.Critical, SCRIPT_NAME, text,
                             parent=main_win)
        dialog.setInformativeText(result)
        dialog.exec_()
        return

    # Returning user the new OTP via the clipboard and a dialog
    QGuiApplication.clipboard().setText(otp)
    QMessageBox.information(main_win, SCRIPT_NAME, '\'%s\' OTP password '
                            'generated:\n\n%s\n\nThis has also been copied to '
                            'the clipboard.' % (slot_name, otp))


def has_slot_config_changed(override_selected_slot_name=None):
    '''Returns true if any slot config is unsaved and/or the key is in a
    decrypted state. Can override the slot name selected in the list, used when
    checking for changes during the currentRowChanged signal'''

    if not override_selected_slot_name is None:
        slot_name = override_selected_slot_name
    else:
        slot_name = ui.otp_list.currentItem().text()

    current_slot_type = (HOTPSlot if ui.htop_radiobutton.isChecked()
                         else TOTPSlot)

    # Includes incomplete key preparation
    common_differences = (slot_name != ui.name_lineedit.text()
            or ui.key_plaintextedit.isEnabled()
            or ui.base32_encoded_checkbox.isChecked() !=
                                        slots_config[slot_name].base32_encoded
            or ui.digits_spinbox.value() != slots_config[slot_name].digits
            or not isinstance(slots_config[slot_name], current_slot_type))
    if common_differences:
        return True

    # Remember this is not an instance type but the type itself on both sides
    if current_slot_type is HOTPSlot:
        return (ui.hotp_counter_spinbox.value() !=
                                                slots_config[slot_name].counter)
    else:
        return (ui.totp_algo_combobox.currentText() !=
                                    slots_config[slot_name].totp_algorithm.name
                or ui.totp_time_step_spinbox.value() !=
                                        slots_config[slot_name].time_step_size
                or ui.totp_start_time_lineedit.text() !=
                                            slots_config[slot_name].start_time
                or ui.totp_now_lineedit.text() !=
                                            slots_config[slot_name].now_time)


def prompt_for_password(is_encryption):
    '''Prompt user for password'''

    # Pop up a password-customised input dialog
    dialog = QInputDialog(main_win)
    text = ('Please provide a password to %s the OTP key/secret with:'
            % ('encrypt' if is_encryption else 'decrypt'))
    dialog.setWindowTitle(SCRIPT_NAME)
    dialog.setLabelText(text)
    dialog.setInputMode(QInputDialog.TextInput)
    dialog.setTextEchoMode(QLineEdit.Password)

    # Default to empty password if the dialog is rejected. Password validation
    # is done with the calling code
    if dialog.exec_() == QDialog.Accepted:
        return dialog.textValue()
    else:
        return ''


def load_slots_config():
    '''Load slots configuration'''

    global slots_config

    # Loading configuration if it exists
    config_directory = os.path.expanduser('~/.config/two-factor-keeper')
    slots_config_file_path = os.path.join(config_directory, 'slots.conf')
    if os.path.exists(slots_config_file_path):

        # Loading YAML document
        try:
            slots_config_text = io.open(slots_config_file_path, 'r').read()
            slots_config = yaml.load(slots_config_text, yaml.CLoader)

        except Exception as e:
            raise Exception('Unable to load slots config from YAML document '
                            '\'%s\':\n\n%s\n\n%s\n'
                            % (slots_config_file_path, str(e),
                               traceback.format_exc()))

    # Empty config is acceptable
    if slots_config is None:
        slots_config = {}


def lock_pushed():
    '''Triggering encryption/decryption of the OTP key based on the state of the
    lock'''

    if ui.encrypt_pushbutton.icon().name() == 'changes-allow':
        encrypt_key()
    else:
        decrypt_key_lock_button()


def otp_slot_add():
    '''Add the current loaded slot details as a new slot'''

    global ignore_slot_change

    new_slot_name = ui.name_lineedit.text()

    try:

        # Saving new slot, exiting on exceptions (dialogs are raised regardless)
        save_slot(True)

    except TwoFactorKeeperException:
        return

    # Ensuring the newly-added slot is selected (save_slot no longer does
    # this to prevent recursion) - making sure spurious 'changes' are not
    # detected
    ignore_slot_change = True
    if ui.otp_list.currentItem().text() != new_slot_name:
        item = ui.otp_list.findItems(new_slot_name,
                                     Qt.MatchFixedString)[0]
        ui.otp_list.setCurrentItem(item)
    ignore_slot_change = False


def otp_slot_apply():
    '''Save any changes to the current slot'''

    # Making sure Apply can save a new slot when no slots are currently defined
    if len(slots_config) == 0:
        save_slot(True)

        # Make sure the first slot is officially loaded (later code expects a
        # row to be selected)
        ui.otp_list.setCurrentRow(0)

    else:
        save_slot(False)


def otp_slot_load(row_number):
    '''Called by the list widget 'currentRowChanged' signal with the new row
    number, and the reset button'''

    global ignore_slot_change
    global last_loaded_slot
    global salt

    # Clearing/resetting the UI when no row is selected (i.e. the last slot has
    # been removed)
    if row_number == -1:
        ui.name_lineedit.clear()
        ui.key_plaintextedit.clear()
        ui.key_plaintextedit.setEnabled(True)
        icon = QIcon.fromTheme('changes-allow')
        ui.encrypt_pushbutton.setIcon(icon)
        ui.base32_encoded_checkbox.setChecked(True)
        salt = None
        ui.htop_radiobutton.setChecked(True)
        ui.totp_algo_combobox.setCurrentIndex(0)
        ui.digits_spinbox.setValue(5)
        ui.hotp_counter_spinbox.setValue(0)
        ui.totp_time_step_spinbox.setValue(30)
        ui.totp_start_time_lineedit.setText('1970-01-01 00:00:00 UTC')
        ui.totp_now_lineedit.setText('now')
        return

    # Fetching slot-to-load's name
    slot_name = ui.otp_list.item(row_number).text()

    # Giving user the option to save any details changed with the previous slot
    # before loading another one, ignoring the first ever slot load, and the
    # load event that happens after the previous slot is removed
    # Currently-selected slot name must be overridden here as the function
    # otherwise expects the otp_list-selected slot name to be accurate, and of
    # course it isn't since from the list widget's perspective, the next slot
    # has been 'loaded'
    # REMEMBER THAT A SLOT MUST SUCCEED LOADING TO UPDATE last_loaded_slot,
    # EVEN IF IT IS POINTLESS
    if (not ignore_slot_change
        and not last_loaded_slot is None
        and last_loaded_slot in slots_config
        and has_slot_config_changed(last_loaded_slot)):
        result = QMessageBox.question(main_win, SCRIPT_NAME, "The \'%s\' OTP "
                                      "slot has unsaved changes - would you like"
                                      " to save these before loading \'%s\'?"
                                      % (last_loaded_slot, slot_name))
        if result == QMessageBox.Yes:

            # Preventing change detection being triggered by the recursive call
            # into this function that happens via both paths below
            ignore_slot_change = True

            # Attempting to save and bailing out on any exception
            try:

                # At this stage the currently-loaded slot having its name
                # changed is always a rename, not addition - so is_slot_new is
                # False. Passing through the original name of the current slot
                save_slot(False, last_loaded_slot)

            except TwoFactorKeeperException:

                # Save attempt failed, so revert the attempted slot change by
                # changing it back to previous value, without triggering
                # recursion in this function
                # Since slot names are unique, only one item will be found
                item = ui.otp_list.findItems(last_loaded_slot,
                                             Qt.MatchFixedString)[0]
                ui.otp_list.setCurrentItem(item)
                return

    # Resetting ignore_slot_change
    ignore_slot_change = False

    # Updating slot-to-load's name (could have been renamed above)
    slot_name = ui.otp_list.item(row_number).text()

    # Making sure the requested slot exists
    if slot_name not in slots_config:
        raise Exception('otp_slot_load called to load slot number %d name '
                        '\'%s\', however no slot by this name exists!\n\n%s'
                        % (row_number, slot_name, traceback.format_exc()))

    # Configuring UI
    ui.name_lineedit.setText(slot_name)
    ui.key_plaintextedit.setPlainText(slots_config[slot_name].key)
    ui.key_plaintextedit.setEnabled(False)
    icon = QIcon.fromTheme('changes-prevent')
    ui.encrypt_pushbutton.setIcon(icon)
    ui.base32_encoded_checkbox.setChecked(slots_config[slot_name].base32_encoded)
    salt = slots_config[slot_name].salt
    ui.digits_spinbox.setValue(slots_config[slot_name].digits)
    if isinstance(slots_config[slot_name], HOTPSlot):
        ui.htop_radiobutton.setChecked(True)
        ui.hotp_counter_spinbox.setValue(slots_config[slot_name].counter)
    else:
        ui.totp_radiobutton.setChecked(True)
        row_number = ui.totp_algo_combobox.findText(slots_config[slot_name]
                                                       .totp_algorithm.name)
        ui.totp_algo_combobox.setCurrentIndex(row_number)
        ui.totp_time_step_spinbox.setValue(slots_config[slot_name].time_step_size)
        ui.totp_start_time_lineedit.setText(slots_config[slot_name].start_time)
        ui.totp_now_lineedit.setText(slots_config[slot_name].now_time)

    # Creating trusted record of last loaded slot name
    last_loaded_slot = slot_name


def otp_slot_remove():
    '''Remove the current slot'''

    # Removing slot and saving
    del slots_config[ui.otp_list.currentItem().text()]
    ui.otp_list.takeItem(ui.otp_list.currentRow())
    save_slots_config()

    # No more slots present results in a currentRowChanged signal, the triggered
    # code then resets/clears the UI


def otp_slot_reset():
    '''Reset any changes to the current slot'''

    global ignore_slot_change

    # Ignoring any changes to the current slot
    ignore_slot_change = True

    # Reloading the slot and saving
    otp_slot_load(ui.otp_list.currentRow())
    save_slots_config()


def save_slot(is_slot_new, old_slot_name=None):
    '''Save the current slot, allowing for the caller to detect failure via
    exceptions. old_slot_name can be overridden when the current selected slot
    in the UI is no longer representative of the loaded slot (e.g. before
    'currentRowChanged' completes)'''

    # Making sure required details have been provided
    slot_name = ui.name_lineedit.text()
    if slot_name == '':
        raise SaveNameNotUniqueException

    # Making sure OTP key is encrypted before saving - note that '=' at the end
    # are effectively noop characters used for padding, and may not be present
    if ui.key_plaintextedit.isEnabled():
        QMessageBox.warning(main_win, SCRIPT_NAME, 'Please set and encrypt the '
                    'key/secret via the lock button before saving the '
                    'OTP slot.')
        ui.key_plaintextedit.setFocus()
        raise SaveKeyNotEncryptedException

    # Checking for slot rename, allowing for old_slot_name to be overridden by
    # caller
    if old_slot_name is None:
        if not ui.otp_list.currentItem() is None:
            old_slot_name = ui.otp_list.currentItem().text()
        else:
            old_slot_name = ''
    if not is_slot_new and slot_name != old_slot_name:

        # Making sure the new name is unique
        if slot_name in slots_config:
            QMessageBox.warning(main_win, SCRIPT_NAME, 'Please choose a unique '
                                'name before saving the OTP slot.')
            ui.name_lineedit.setFocus()
            raise SaveNameNotUniqueException

        # Removing old slot
        del slots_config[old_slot_name]

    # Making sure a new slot has a unique name
    elif is_slot_new and slot_name in slots_config:
        QMessageBox.warning(main_win, SCRIPT_NAME, 'Please choose a unique '
                            'name before saving the OTP slot.')
        ui.name_lineedit.setFocus()
        raise SaveNameNotUniqueException

    # Creating new slot object to ease switching between slot types, regardless
    # of whether the slot is new or not
    # pylint:disable=redefined-variable-type
    key = get_key_contents()
    base32_encoded = ui.base32_encoded_checkbox.isChecked()
    digits = ui.digits_spinbox.value()
    if ui.htop_radiobutton.isChecked():
        counter = ui.hotp_counter_spinbox.value()
        slot = HOTPSlot(slot_name, key, base32_encoded, salt, digits, counter)
    else:
        totp_algorithm = TOTPAlgorithm[ui.totp_algo_combobox.currentText()]
        time_step_size = ui.totp_time_step_spinbox.value()
        start_time = ui.totp_start_time_lineedit.text()
        now_time = ui.totp_now_lineedit.text()
        slot = TOTPSlot(slot_name, key, base32_encoded, salt, digits,
                        totp_algorithm, time_step_size, start_time, now_time)

    # Replacing/adding the slot and saving new config
    slots_config[slot_name] = slot
    save_slots_config()

    # Renaming list entry on slot renames - note in the case of the user trying
    # to move away from a slot that has an unsaved rename, the currentItem will
    # be the slot that is being moved to, not the slot being saved
    # findItems will always return one item here
    if not is_slot_new and slot_name != old_slot_name:
        item = ui.otp_list.findItems(old_slot_name, Qt.MatchFixedString)[0]
        item.setText(slot_name)

    # Adding the new slot (sorting is now done at the end)
    # DO NOT remove the current item/do anything to change the current item etc
    # - it turns out that the recursion back into this function is just too
    # messy even with special flags etc. Luckily Qt can sort the list on its
    # own without changing the current selected row
    elif is_slot_new:
        ui.otp_list.addItems([slot_name])

    ui.otp_list.sortItems(Qt.AscendingOrder)


def save_slots_config():
    '''Save the slots configuration'''

    # Making sure configuration directory is available
    config_directory = os.path.expanduser('~/.config/two-factor-keeper')
    os.makedirs(config_directory, exist_ok=True)

    with io.open(os.path.join(config_directory, 'slots.conf'), 'w') as slots_config_file:
        yaml.dump(slots_config, slots_config_file, yaml.CDumper)


# Initialise Qt application instance
app = QApplication(sys.argv)

# Create main widget to host the generated UI in, and an instance of the class
# describing the UI
main_win = QMainWindow()
ui = Ui_MainWindow()

# Instantiate the UI in the widget
ui.setupUi(main_win)

# Hook up remaining signals/slots
ui.add_pushbutton.clicked.connect(otp_slot_add)
ui.apply_pushbutton.clicked.connect(otp_slot_apply)
ui.clear_key_pushbutton.clicked.connect(clear_key)
ui.encrypt_pushbutton.clicked.connect(lock_pushed)
ui.generate_otp_pushbutton.clicked.connect(generate_otp)
ui.otp_list.currentRowChanged.connect(otp_slot_load)
ui.reset_pushbutton.clicked.connect(otp_slot_reset)
ui.remove_pushbutton.clicked.connect(otp_slot_remove)

# Hooking up actions
ui.actionAbout.triggered.connect(about)
ui.actionExit.triggered.connect(sys.exit)

# Configuring OTP slots, alphabetically-sorted
load_slots_config()
ui.otp_list.addItems(slots_config.keys())
ui.otp_list.sortItems(Qt.AscendingOrder)
if len(slots_config) > 0:
    ui.otp_list.setCurrentRow(0)
ui.otp_list.setFocus()
main_win.show()

# Run mainloop
sys.exit(app.exec_())
