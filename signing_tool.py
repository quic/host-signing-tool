# Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause-Clear

# K2L: Host Tool For Image Signing(efi.bin & dtb.bin).
# Author: quic_chishah@quicinc.com - Feb, 2024

import os
import sys
import platform
import subprocess
import shlex
import socket
import shutil
import configparser
import glob
from enum import Enum

class SignImage(Enum):
    SIGN_EFI = 1
    SIGN_DTB = 2
    SIGN_ERR = 3

class SelectPath(Enum):
    PATH_LOCAL = 1
    PATH_REMOTE = 2
    PATH_ERR = 3

class SelectOperation(Enum):
    OP_SIGN = 1
    OP_COMBINE_DTB = 2
    OP_ERR = 3

class CombineOperationType(Enum):
    CO_WITH_OLD_DTB = 1
    CO_WITHOUT_OLD_DTB = 2
    CO_ERR = 3

#Macros
DEFINE_PYTHON_MAJOR_VER = 3
OS_NONE = 0
OS_WINDOWS = 1
OS_LINUX = 2

os_type = OS_NONE
global file_path_type
global private_key_path
global config_status
remote_host = "host"
user_name = "username"
remote_path = "path"
image_type = SignImage.SIGN_ERR
operation = SelectOperation.OP_ERR
combine_dtb_type = CombineOperationType.CO_ERR
global cmd_output
unsigned_bin_directory = 'unsigned_binaries/'
signed_bin_directory = 'signed_binaries/'
combined_dtb_directory = "unsigned_combined_dtb_bin/"
local_efi_file_path  = unsigned_bin_directory + 'efi.bin'
local_dtb_file_path  = unsigned_bin_directory + 'dtb.bin'
keys_directory = 'keys/'
dtb_files_directory = 'dtb_files/'
tmp_keys_directory = 'temp_keys/'
tmp_dtb_files_directory = 'temp_dtb_files/'
tmp_combined_dtb_directory = 'temp_combined_dtb_bin/'
combined_dtb_file_name = tmp_combined_dtb_directory + 'combined-dtb.dtb'
combined_dtb_bin_path = combined_dtb_directory + 'dtb.bin'
mount_directory = 'efimountedbin/'
loader_mount_directory = mount_directory + 'loader/'
keys_mount_directory = loader_mount_directory + 'keys/'
authkeys_mount_directory = keys_mount_directory + 'authkeys/'
local_key_path = keys_directory + 'db.key'
local_cert_path = keys_directory + 'db.crt'
local_pk_auth_path = keys_directory + 'PK.auth'
local_kek_auth_path = keys_directory + 'KEK.auth'
local_db_auth_path = keys_directory + 'db.auth'
unsigned_boot_img_path = mount_directory + 'EFI/BOOT/bootaa64.efi'
unsigned_linux_img_path = mount_directory + 'EFI/Linux/'
unsigned_vmlinuz_img_path = mount_directory + 'ostree'
unsigned_dtb_file_path_efi = mount_directory + 'dtb/'
unsigned_dtb_file_path_dtb = mount_directory
signed_boot_img_path = unsigned_bin_directory + 'bootaa64.efi'
temp_loader_conf_path = unsigned_bin_directory + 'loader.conf'
loader_conf_path = loader_mount_directory + 'loader.conf'

'''
Config file variable
'''
global config_common_operation
global config_common_image_type
global config_common_file_path
global config_common_local_machine_private_key_path
global config_common_loader_conf_timeout
global config_common_combine_dtb_type

global config_efi_config_efi_remote_hostname
global config_efi_config_efi_remote_username
global config_efi_config_efi_remote_filepath

global config_keys_config_keys_remote_hostname
global config_keys_config_keys_remote_username
global config_keys_config_keys_remote_filepath

global config_dtb_config_dtb_remote_hostname
global config_dtb_config_dtb_remote_username
global config_dtb_config_dtb_remote_filepath

global config_combine_dtb_remote_hostname
global config_combine_dtb_remote_username
global config_combine_dtb_remote_filepath

def script_prerequisite():
    print("###################################################################")
    print("SCRIPT PRE-REQUISITES")
    print("1. This script only supports running on Linux machine right now.")
    print("2. Select appropriate options in config.ini file before running script")
    print("3. Run this script with python3 - i.e., - python3 signing_tool.py")
    print("4. Host machine must have - openssl, sbsign installed")
    print("5. Required python3 modules - pip, subprocess, shlex, socket, shutil, glob")
    print("###################################################################\n")

def script_usage_msg():
    print("###################################################################")
    print("SCRIPT USAGE MESSAGE:")
    print("This script will help with TWO operations(Performs one operation at a time): 1. Sign EFI/DTB, 2. Combine DTB files")
    print("Operation - 1. Sign EITHER bootaa64.efi, Linux EFI image, vmlinuz image from efi.bin OR dtb files from dtb.bin")
    print("1.1. To sign above images - this script will require 'keys' as well")
    print("1.2. efi.bin/dtb.bin and 'keys' can be present at local machine or at some remote location")
    print("1.3. To use this script first choose where this files are present - i.e., Remote Path or Local path")
    print("1.4. This script only support copy files from remote linux machine. Copy from Windows machine is not yet supported")
    print("1.5. After signing - this script will update loader.conf in efi.bin and copy 'AUTH' keys in efi.bin/dtb.bin")
    print(f"1.6. At the end - the newly signed efi.bin/dtb.bin will be copied to {signed_bin_directory} directory")
    print("Operation - 2. Create combined-dtb.dtb from available *.dtb files")
    print("2.1. This script can create a new dtb.bin by combining all the dtb files into combined-dtb.dtb files")
    print("2.2. Same as Operation-1, dtb.bin & dtb files can be present locally or in a remote linux path and can be copied to local location")
    print("2.3. If user selects operation with old dtb.bin file - this script will append the other available dtb files to original combined-dtb.dtb file from original dtb.bin")
    print("2.4. If there is no dtb.bin file - this script will combine all available dtb files and create new combined-dtb.dtb file and pack it as dtb.bin(VFAT)")
    print("2.4. If user selects operation without old dtb.bin file - this script will combine all available dtb files and create new combined-dtb.dtb file and pack it as dtb.bin(VFAT)")
    print(f"2.5. This script expects old dtb.bin under {unsigned_bin_directory} directory - if user selects operation with old dtb.bin")
    print(f"2.5. This script expects dtb files under {dtb_files_directory} directory")
    print(f"2.6. At the end - the newly created dtb.bin(with combined-dtb.dtb) will be copied to {combined_dtb_directory} directory")
    print("###################################################################")
    print("\nBEGIN THE PROCESS\n")

def select_path_type():
    print("###################################################################")
    print("Select any one option where required files are present")
    print("1. Use Local machine path")
    print("2. Use Remote machie path - THIS MUST BE A LINUX MACHINE PATH")
    print("\nHelp: For Option-1, Please copy below files in the same location as this script")
    print(f"1. Create {unsigned_bin_directory} directory and copy efi.bin/dtb.bin to that directory")
    print(f"2. Create {keys_directory} directory and copy all required keys/cert/auth to that directory.")
    print("(e.g.- Required Keys/Cert/Auth files - db.key, db.crt, PK.auth, KEK.auth, db.auth)")
    print("###################################################################")
    choice = input("Enter your choice: ")
    if choice == "1":
        return SelectPath.PATH_LOCAL
    elif choice == "2":
        return SelectPath.PATH_REMOTE
    else:
        return SelectPath.PATH_ERR

def read_config():
    global config_status

    global config_common_operation
    global config_common_image_type
    global config_common_file_path
    global config_common_local_machine_private_key_path
    global config_common_loader_conf_timeout
    global config_common_combine_dtb_type

    global config_efi_config_efi_remote_hostname
    global config_efi_config_efi_remote_username
    global config_efi_config_efi_remote_filepath

    global config_keys_config_keys_remote_hostname
    global config_keys_config_keys_remote_username
    global config_keys_config_keys_remote_filepath

    global config_dtb_config_dtb_remote_hostname
    global config_dtb_config_dtb_remote_username
    global config_dtb_config_dtb_remote_filepath

    global config_combine_dtb_remote_hostname
    global config_combine_dtb_remote_username
    global config_combine_dtb_remote_filepath

    # Create a ConfigParser object

    config = configparser.ConfigParser()

    # Read the INI file
    filenames = config.read('config.ini')

    # Check if the file(s) was/were loaded successfully
    if not filenames:
        print("Error: The config file was not found or could not be read.")
        return 1

    # Define the configurations
    configs = ['common', 'efi_config', 'keys_config', 'dtb_config', 'combine_dtb_config']

    # Loop through the configurations
    for conf in configs:
        if conf == 'common':
            config_common_operation = config.get(conf, 'operation')
            config_common_image_type = config.get(conf, 'image_type')
            config_common_file_path = config.get(conf, 'file_path')
            config_common_local_machine_private_key_path = config.get(conf, 'local_machine_private_key_path')
            config_common_loader_conf_timeout = config.get(conf, 'loader_conf_timeout')
            config_common_combine_dtb_type = config.get(conf, 'combine_dtb_type')
        if conf == 'efi_config':
            config_efi_config_efi_remote_hostname = config.get(conf, 'efi_remote_hostname')
            config_efi_config_efi_remote_username = config.get(conf, 'efi_remote_username')
            config_efi_config_efi_remote_filepath = config.get(conf, 'efi_remote_filepath')
        if conf == 'keys_config':
            config_keys_config_keys_remote_hostname = config.get(conf, 'keys_remote_hostname')
            config_keys_config_keys_remote_username = config.get(conf, 'keys_remote_username')
            config_keys_config_keys_remote_filepath = config.get(conf, 'keys_remote_filepath')
        if conf == 'dtb_config':
            config_dtb_config_dtb_remote_hostname = config.get(conf, 'dtb_remote_hostname')
            config_dtb_config_dtb_remote_username = config.get(conf, 'dtb_remote_username')
            config_dtb_config_dtb_remote_filepath = config.get(conf, 'dtb_remote_filepath')
        if conf == "combine_dtb_config":
            config_combine_dtb_remote_hostname = config.get(conf, 'combine_dtb_remote_hostname')
            config_combine_dtb_remote_username = config.get(conf, 'combine_dtb_remote_username')
            config_combine_dtb_remote_filepath = config.get(conf, 'combine_dtb_remote_filepath')
    return 0

def execute_command(command):
    global cmd_output
    # Define a list of allowed commands
    allowed_commands = ['scp', 'sbsign', 'sudo', 'touch', 'cp', 'rm', 'mkdir', 'mkfs.vfat', 'mcopy']

    # Split the command into a list
    command_list = shlex.split(command)

    # Check if the command is allowed
    if command_list[0] not in allowed_commands:
        print(f"Error: '{command_list[0]}' is not an allowed command.")
        return 1 #Failure

    # Escape the arguments
    command_list[1:] = [shlex.quote(arg) for arg in command_list[1:]]

    try:
        # Execute the command
        process = subprocess.run(command_list, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

        # If the command was successful
        print("Command executed successfully.")
        print(f"Output: {process.stdout}")
        cmd_output = process.stdout #Use this when command o/p is required
        print(f"Return Code: {process.returncode}")
        return 0 #Success
    except subprocess.CalledProcessError as e:
        # If the command failed
        print("Command execution failed.")
        print(f"Error: {e.stderr}")
        print(f"Return Code: {e.returncode}")
        return 1 #Failure
    except Exception as e:
        # If there was another exception
        print(f"Failed to execute command: {e}")
        return 1 #Failure

def check_if_necessary_files_available_for_combining_dtb():
    dtb_files_count = 0

    if combine_dtb_type == CombineOperationType.CO_WITH_OLD_DTB:
        if not os.path.isdir(unsigned_bin_directory):
            print(f"Directory {unsigned_bin_directory} does not exist - Exiting the tool!")
            return 1 #Failure
        if not os.path.exists(local_dtb_file_path):
            print(f"File {local_dtb_file_path} does not exist - Exiting the tool!")
            return 1 #Failure
    if not os.path.isdir(dtb_files_directory):
        print(f"Directory {dtb_files_directory} does not exist - Exiting the tool!")
        return 1 #Failure
    for filename in os.listdir(dtb_files_directory):
        if filename.endswith('.dtb'):
            dtb_files_count = dtb_files_count + 1

    print(f"No. of dtb files available in {dtb_files_directory} are {dtb_files_count}")

    if dtb_files_count > 0:
        return 0 #Success
    else:
        return 1 #Failure

def check_if_necessary_files_available_for_signing():
    if not os.path.isdir(unsigned_bin_directory):
        print(f"Directory {unsigned_bin_directory} does not exist - Exiting the tool!")
        return 1 #Failure

    if image_type == SignImage.SIGN_EFI:
        if not os.path.exists(local_efi_file_path):
            print(f"File {local_efi_file_path} does not exist - Exiting the tool!")
            return 1 #Failure
    elif image_type == SignImage.SIGN_DTB:
        if not os.path.exists(local_dtb_file_path):
            print(f"File {local_dtb_file_path} does not exist - Exiting the tool!")
            return 1 #Failure

    if not os.path.isdir(keys_directory):
        print(f"Directory {keys_directory} does not exist - Exiting the tool!")
        return 1 #Failure
    if not os.path.exists(local_key_path):
        print(f"File {local_key_path} does not exist - Exiting the tool!")
        return 1 #Failure
    if not os.path.exists(local_cert_path):
        print(f"File {local_cert_path} does not exist - Exiting the tool!")
        return 1 #Failure
    if not os.path.exists(local_pk_auth_path):
        print(f"File {local_pk_auth_path} does not exist - Exiting the tool!")
        return 1 #Failure
    if not os.path.exists(local_kek_auth_path):
        print(f"File {local_kek_auth_path} does not exist - Exiting the tool!")
        return 1 #Failure
    if not os.path.exists(local_db_auth_path):
        print(f"File {local_db_auth_path} does not exist - Exiting the tool!")
        return 1 #Failure
    return 0


def check_if_necessary_files_available():
    if operation == SelectOperation.OP_SIGN:
        return check_if_necessary_files_available_for_signing()
    elif operation == SelectOperation.OP_COMBINE_DTB:
        return check_if_necessary_files_available_for_combining_dtb()
    else:
        print("Wrong operation found - Exiting the tool!")
        return 1 #Failure

def mount_unmount_device(device, mount_point, option):
    try:
        if option == 'mount':
            result = subprocess.run(["sudo", "mount", device, mount_point, "-w"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif option == 'umount':
            result = subprocess.run(["sudo", "umount", mount_point], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.returncode}, {e.output}, {e.stderr}")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

#TODO - Error checking - last priority
def create_new_directory(dirname):
    #Check if the directory exists, if so delete it
    if os.path.exists(dirname):
        shutil.rmtree(dirname)
    #Create the destination directory
    os.makedirs(dirname, exist_ok=True)

def rename_directory(old_dir_name, new_dir_name):
    try:
        os.rename(old_dir_name, new_dir_name)
        print(f"Directory '{old_dir_name}' has been successfully renamed to '{new_dir_name}'.")
    except FileNotFoundError:
        print(f"Directory '{old_dir_name}' does not exist.")
    except Exception as e:
        print(f"Error during renaming: {e}")

def delete_directory(directory_path):
    try:
        if os.path.exists(directory_path):
            if os.path.isdir(directory_path):
                # Directory exists
                if not os.listdir(directory_path):
                    # Directory is empty, use os.rmdir
                    os.rmdir(directory_path)
                else:
                    # Directory is non-empty, use shutil.rmtree
                    shutil.rmtree(directory_path)
                print(f"Directory '{directory_path}' has been successfully deleted.")
                return 0
            else:
                print(f"'{directory_path}' is not a directory.")
        else:
            print(f"Directory '{directory_path}' does not exist.")
    except Exception as e:
        print(f"Error during deletion: {e}")
    return 1

def select_combine_operation_type():
    print("\n###################################################################")
    print("Select one of the below combining operations to be performed by this script")
    print("1. Combine with old DTB -> To combine old dtb.bin with new *.dtb files to create new DTB.BIN(combined-dtb.dtb)")
    print("2. Combine without old DTB -> To only combine *.dtb files into common DTB.BIN(combined-dtb.dtb)")
    print("###################################################################")
    choice = input("Enter your choice: ")
    if choice == "1":
        return CombineOperationType.CO_WITH_OLD_DTB
    elif choice == "2":
        return CombineOperationType.CO_WITHOUT_OLD_DTB
    else:
        return CombineOperationType.CO_ERR

def select_operation_type():
    print("\n###################################################################")
    print("Select one of the below operations to be performed by this script")
    print("1. Sign Imange -> TO SIGN EFI.BIN/DTB.BIN")
    print("2. Combine DTB -> TO combine all the DTBs into common DTB.BIN(combined-dtb.dtb)")
    print("###################################################################")
    choice = input("Enter your choice: ")
    if choice == "1":
        return SelectOperation.OP_SIGN
    elif choice == "2":
        return SelectOperation.OP_COMBINE_DTB
    else:
        return SelectOperation.OP_ERR

def select_image_type():
    print("\n###################################################################")
    print("Select one of the below files for signing")
    print("1. EFI -> TO SIGN EFI.BIN")
    print("2. DTB -> TO SIGN DTB.BIN")
    print("###################################################################")
    choice = input("Enter your choice: ")
    if choice == "1":
        return SignImage.SIGN_EFI
    elif choice == "2":
        return SignImage.SIGN_DTB
    else:
        return SignImage.SIGN_ERR

def get_file_path():
    while True:
        print("Please select an option:")
        print("1. Enter file path manually")
        print("2. Browse file path")
        choice = input("Enter your choice: ")
        if choice == "1":
            file_path = input("Enter file path: ")
            if os.path.isfile(file_path):
                return file_path
            else:
                # print("Invalid file path")
                # Return error for invalid file path
                return SignImage.SIGN_ERR
        elif choice == "2":
            from tkinter import Tk
            from tkinter.filedialog import askopenfilename
            root = Tk()
            root.withdraw()
            file_path = askopenfilename()
            if os.path.isfile(file_path):
                return file_path
            else:
                # print("Invalid file path")
                # Return error for invalid file path
                return SignImage.SIGN_ERR
        else:
            # print("Invalid choice")
            # Return error for invalid file path
            return SignImage.SIGN_ERR

def get_linux_file_path(file_type):
    global remote_host
    global user_name
    global remote_path

    global config_status

    global config_efi_config_efi_remote_hostname
    global config_efi_config_efi_remote_username
    global config_efi_config_efi_remote_filepath

    global config_keys_config_keys_remote_hostname
    global config_keys_config_keys_remote_username
    global config_keys_config_keys_remote_filepath

    global config_dtb_config_dtb_remote_hostname
    global config_dtb_config_dtb_remote_username
    global config_dtb_config_dtb_remote_filepath

    global config_combine_dtb_remote_hostname
    global config_combine_dtb_remote_username
    global config_combine_dtb_remote_filepath

    if config_status == 0 and file_type == 'efi':
        #Config is available and getting info about efi file
        if config_efi_config_efi_remote_hostname:
            #Read from config if available
            remote_host = config_efi_config_efi_remote_hostname
            print(f"[*****Selecting remote machine ip/name as: {remote_host} from config file for further operation*****]")
        else:
            #Ask user
            remote_host = input("Enter remote machine ip/name: ")

        if config_efi_config_efi_remote_username:
            #Read from config if available
            user_name = config_efi_config_efi_remote_username
            print(f"[*****Selecting remote machine username as: {user_name} from config file for further operation*****]")
        else:
            #Ask user
            user_name = input("Enter your usernme for remote machine: ")

        if config_efi_config_efi_remote_filepath:
            #Read from config if available
            remote_path = config_efi_config_efi_remote_filepath
            print(f"[*****Selecting remote machine file path as: {remote_path} from config file for further operation*****]")
        else:
            #Ask user
            remote_path = input("Enter file path on remote machine: ")

    elif config_status == 0 and file_type == 'keys':
        #Config is available and getting info about keys directory
        if config_keys_config_keys_remote_hostname:
            #Read from config if available
            remote_host = config_keys_config_keys_remote_hostname
            print(f"[*****Selecting remote machine ip/name as: {remote_host} from config file for further operation*****]")
        else:
            #Ask user
            remote_host = input("Enter remote machine ip/name: ")

        if config_keys_config_keys_remote_username:
            #Read from config if available
            user_name = config_keys_config_keys_remote_username
            print(f"[*****Selecting remote machine username as: {user_name} from config file for further operation*****]")
        else:
            #Ask user
            user_name = input("Enter your usernme for remote machine: ")

        if config_keys_config_keys_remote_filepath:
            #Read from config if available
            remote_path = config_keys_config_keys_remote_filepath
            print(f"[*****Selecting remote machine file path as: {remote_path} from config file for further operation*****]")
        else:
            #Ask user
            remote_path = input("Enter file path on remote machine: ")

    elif config_status == 0 and file_type == 'dtb':
        #Config is available and getting info about dtb file
        if config_dtb_config_dtb_remote_hostname:
            #Read from config if available
            remote_host = config_dtb_config_dtb_remote_hostname
            print(f"[*****Selecting remote machine ip/name as: {remote_host} from config file for further operation*****]")
        else:
            #Ask user
            remote_host = input("Enter remote machine ip/name: ")

        if config_dtb_config_dtb_remote_username:
            #Read from config if available
            user_name = config_dtb_config_dtb_remote_username
            print(f"[*****Selecting remote machine username as: {user_name} from config file for further operation*****]")
        else:
            #Ask user
            user_name = input("Enter your usernme for remote machine: ")

        if config_dtb_config_dtb_remote_filepath:
            #Read from config if available
            remote_path = config_dtb_config_dtb_remote_filepath
            print(f"[*****Selecting remote machine file path as: {remote_path} from config file for further operation*****]")
        else:
            #Ask user
            remote_path = input("Enter file path on remote machine: ")

    elif config_status == 0 and file_type == 'combine_dtb':
        #Config is available and getting info about dtb file
        if config_combine_dtb_remote_hostname:
            #Read from config if available
            remote_host = config_combine_dtb_remote_hostname
            print(f"[*****Selecting remote machine ip/name as: {remote_host} from config file for further operation*****]")
        else:
            #Ask user
            remote_host = input("Enter remote machine ip/name: ")

        if config_combine_dtb_remote_username:
            #Read from config if available
            user_name = config_combine_dtb_remote_username
            print(f"[*****Selecting remote machine username as: {user_name} from config file for further operation*****]")
        else:
            #Ask user
            user_name = input("Enter your usernme for remote machine: ")

        if config_combine_dtb_remote_filepath:
            #Read from config if available
            remote_path = config_combine_dtb_remote_filepath
            print(f"[*****Selecting remote machine file path as: {remote_path} from config file for further operation*****]")
        else:
            #Ask user
            remote_path = input("Enter file path on remote machine: ")

    else:
        #Config is not available - get info from user
        remote_host = input("Enter remote machine ip/name: ")
        user_name = input("Enter your usernme for remote machine: ")
        remote_path = input("Enter file path on remote machine: ")

    # Construct the SSH command to check file existence
    ssh_command = f"ssh {remote_host} '[ -e {remote_path} ] && echo exists || echo does_not_exist'"
    print(f"----->{ssh_command}")

    # Execute the SSH command and capture the output
    result = os.popen(ssh_command).read().strip()

    if result == "exists":
        print(f"File '{remote_path}' exists on {remote_host}.")
    else:
        print(f"File '{remote_path}' does not exist on {remote_host}.")
        raise Exception("Invalid file path - Exiting the tool!")

def copy_directory(destination_directory):
    global os_type
    global remote_host
    global user_name
    global remote_path
    global private_key_path

    """
    #Step-1: Get hostname/ip address of machine where keys are saved and
                file path of that directory from remote machine
    """
    if os_type == OS_LINUX:
        if operation == SelectOperation.OP_SIGN:
            get_linux_file_path('keys') #Get hostname and path
            keys_remote_path = f"//{remote_host}{remote_path}" #Construct file path
        elif operation == SelectOperation.OP_COMBINE_DTB:
            get_linux_file_path('combine_dtb') #Get hostname and path
            keys_remote_path = f"//{remote_host}{remote_path}" #Construct file path
    else: #THIS IS For Windows system
        keys_remote_path = get_file_path()

    #Step-2: Check network connectivity
    try:
        socket.create_connection((remote_host, 22), 2)
    except OSError:
        print(f"Error: Could not connect to {remote_host} on port 22.")
        exit(1)

    #TODO - SCP with windows path is not working
    #Step-3: Copy all the keys from remote path to local machine & error check
    copy_dir_scp_cmd = f"scp -r -i {private_key_path} {user_name}@{remote_host}:{remote_path} {destination_directory}"
    print(f"SCP: {copy_dir_scp_cmd}")
    status = execute_command(copy_dir_scp_cmd)
    if status != 0:
        print("Failed to copy keys from remote machine - Exiting the tool!")
        sys.exit(status)

'''
copy_image() copies unsigned efi.bin/dtb.bin from remote machine(Currently supports copy from only linux machine)
'''
def copy_image():
    global os_type
    global remote_host
    global user_name
    global remote_path
    global image_type
    global operation
    global private_key_path

    #print(f"----->{os_type}")
    """
    #Step-1: Get hostname/ip address of machine where 'bin' is saved and
                file path of the 'bin' file
    """
    if os_type == OS_LINUX:
        if operation == SelectOperation.OP_SIGN:
            if image_type == SignImage.SIGN_EFI:
                get_linux_file_path('efi') #Get hostname and path
            elif image_type == SignImage.SIGN_DTB:
                get_linux_file_path('dtb')
        elif operation == SelectOperation.OP_COMBINE_DTB:
            get_linux_file_path('dtb')
        else:
            raise Exception("Invalid operation - Exiting the tool!")
        bin_file_path = f"//{remote_host}{remote_path}"
    else: #THIS IS For Windows system - Only remote file selection on Windows machine working. Copy from that location is not working
        print("Please provide path for 'bin' file")
        bin_file_path = get_file_path()
        if bin_file_path == SignImage.SIGN_ERR:
            raise Exception("Invalid file path for 'bin' file - Exiting the tool!")

    #Step-2: Check network connectivity
    try:
        socket.create_connection((remote_host, 22), 2)
    except OSError:
        print(f"Error: Could not connect to {remote_host} on port 22.")
        exit(1)

    print(f"Selected file path: {bin_file_path}")
    #Step-3: Check if selected file is efi.bin/dtb.bin or not
    selected_bin_file = os.path.basename(bin_file_path)
    print(f"selected_bin_file: {selected_bin_file}")

    if operation == SelectOperation.OP_SIGN:
        if image_type == SignImage.SIGN_EFI:
            if not selected_bin_file == "efi.bin":
                raise Exception("This is not efi.bin file - Exiting the tool!")
            destination_file_path = local_efi_file_path
        elif image_type == SignImage.SIGN_DTB:
            if not selected_bin_file == "dtb.bin":
                raise Exception("This is not dtb.bin file - Exiting the tool!")
            destination_file_path = local_dtb_file_path
        else:
            raise Exception("Wrong image type is selected - Exiting the tool!")
    elif operation == SelectOperation.OP_COMBINE_DTB:
        if not selected_bin_file == "dtb.bin":
            raise Exception("This is not dtb.bin file - Exiting the tool!")
        destination_file_path = local_dtb_file_path
    else:
        raise Exception("Invalid operation - Exiting the tool!")

    print(f"destination_file_path: {destination_file_path}")
    #Step-4: Check if the destination directory exists, if so delete it
    destination_directory = os.path.dirname(destination_file_path)
    create_new_directory(destination_directory)

    #TODO 1 - SCP with windows path is not working
    #TODO 2 - Try to do scp with execute_command() function
    #Step-5: Copy efi.bin/dtb.bin from remote path to local machine & error check
    command = f"scp -i {private_key_path} {user_name}@{remote_host}:{remote_path} {destination_file_path}"

    try:
        # Execute the command
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

        # Read the output and error in chunks to handle large files
        while True:
            output = process.stdout.readline() # type: ignore
            error = process.stderr.readline() # type: ignore

            # Check if the process has finished
            if output == '' and process.poll() is not None:
                break

            if output:
                print(f"Output: {output.strip()}")
            if error:
                print(f"Error: {error.strip()}")

        # Check the return code
        rc = process.poll()
        if rc != 0:
            print(f"Command failed with return code {rc}")
    except Exception as e:
        print(f"Failed to execute command: {e}")

def copy_remote_files():
    global private_key_path

    #Read from config if available
    #Step-1.1: Get the private key path for ssh
    if config_status == 0 and config_common_local_machine_private_key_path:
        private_key_path = config_common_local_machine_private_key_path
        print(f"[*****Selecting local machine private key path as: {private_key_path} from config file for further operation*****]")
    else:
        #Ask user
        private_key_path = input("Enter Private Key Path of SSH for this machine(i.e., path for </.ssh/id_rsa>): ")
    # Check if the private key file exists
    if not os.path.isfile(private_key_path):
        print(f"Error: Private key file '{private_key_path}' does not exist.")
        exit(1)

    #Step-1.2: Copy the required image to local machine
    if (operation == SelectOperation.OP_COMBINE_DTB and combine_dtb_type == CombineOperationType.CO_WITHOUT_OLD_DTB):
        print("########### Moving ahead without copying dtb.bin from remote location as combine_dtb_type is selected as combine_without_old_dtb in config.ini ###########\n")
    else:
        print("\n###################################################################")
        print("Provide details to copy 'bin' file from remote machine...")
        copy_image()
        print("###################################################################")

    if operation == SelectOperation.OP_SIGN:
        #Step-1.3: Copy the keys to local machine
        print("\n###################################################################")
        print("Provide details to copy 'keys' from remote machine...")
        #Create keys directory to copy keys
        create_new_directory(tmp_keys_directory)
        #Copy keys in "keys_directory" from remote machine
        copy_directory(tmp_keys_directory)
        remote_directory = os.path.basename(remote_path)
        remote_directory = tmp_keys_directory + remote_directory
        print(f"remote_directory---------------: {remote_directory}")
        rename_directory(remote_directory, keys_directory)
        delete_directory(tmp_keys_directory)
        print("###################################################################")
    elif operation == SelectOperation.OP_COMBINE_DTB:
        #Step-1.3: Copy the *.dtb files to local machine
        print("\n###################################################################")
        print("Provide details to copy *.dtb files directory from remote machine...")
        #Create temp_dtb_files directory to copy *.dtb files
        create_new_directory(tmp_dtb_files_directory)
        #Copy *.dtb files in "temp_dtb_files" from remote machine
        copy_directory(tmp_dtb_files_directory)
        remote_directory = os.path.basename(remote_path)
        remote_directory = tmp_dtb_files_directory + remote_directory
        print(f"remote_directory---------------: {remote_directory}")
        rename_directory(remote_directory, dtb_files_directory)
        delete_directory(tmp_dtb_files_directory)
        print("###################################################################")
    else:
        raise Exception("Wrong operation is selected - Exiting the tool!")

def copy_metadata_from_old_dtb(source_mounted_dtb_dir, destination_dir):
    for dirpath, dirnames, filenames in os.walk(source_mounted_dtb_dir):
        # Construct the destination directory
        dst_path = os.path.join(destination_dir, os.path.relpath(dirpath, source_mounted_dtb_dir))
        os.makedirs(dst_path, exist_ok=True)

        for filename in filenames:
            # Exclude .dtb files
            if not filename.endswith('.dtb'):
                # Construct the full file paths
                src_file = os.path.join(dirpath, filename)
                dst_file = os.path.join(dst_path, filename)

                # Copy the file
                shutil.copy2(src_file, dst_file)

def init_dtb_combine_process():
    print("\n########### Initializing dtb combining process ###########\n")
    if file_path_type == SelectPath.PATH_REMOTE:
        print("\nWe need to copy dtb.bin and *.dtb files from remote machine - Please provide required details")
        copy_remote_files()

    #Step-2: Check if unsigned_bin_directory & keys_directory are present or not
    status = check_if_necessary_files_available()
    if status != 0:
        print("Some necessary files are missing - Exiting the tool!")
        sys.exit(status)

    #Step-3: Create mount point & mount dtb.bin if combining with old dtb.bin
    if combine_dtb_type == CombineOperationType.CO_WITH_OLD_DTB:
        print(f"Mounting dtb.bin to {mount_directory}...")
        create_new_directory(mount_directory)
        mount_unmount_device(local_dtb_file_path, mount_directory, 'mount')

    #Step-4: Create {unsigned_bin_directory} directory when combine_dtb_type == combine_without_old_dtb is selected for furthur operation
    if combine_dtb_type == CombineOperationType.CO_WITHOUT_OLD_DTB:
        print(f"Create {unsigned_bin_directory}...")
        create_new_directory(unsigned_bin_directory)

    #Step-5: Create {tmp_combined_dtb_directory} and copy all original dtb.bin data to it
    print(f"Create {tmp_combined_dtb_directory}...")
    create_new_directory(tmp_combined_dtb_directory)

    if combine_dtb_type == CombineOperationType.CO_WITH_OLD_DTB:
        print(f"Copying all data from {mount_directory} except .dtb file to {tmp_combined_dtb_directory}")
        copy_metadata_from_old_dtb(mount_directory, tmp_combined_dtb_directory)

def init_signing_process():
    print("\n########### Initializing signing process ###########\n")
    #Step-1: Follow this if Remote path is selected to copy 'bin' and 'keys'
    if file_path_type == SelectPath.PATH_REMOTE:
        print("\nWe need to copy 'bin' and 'keys' from remote machine - Please provide required details")
        copy_remote_files()

    #Step-2: Check if unsigned_bin_directory & keys_directory are present or not
    status = check_if_necessary_files_available()
    if status != 0:
        print("Some necessary files are missing - Exiting the tool!")
        sys.exit(status)

    #Step-3: Mount efi/dtb.bin
    #Create mount point & mount efi.bin/dtb.bin
    print(f"Mounting efi.bin/dtb.bin to {mount_directory}...")
    create_new_directory(mount_directory)
    if image_type == SignImage.SIGN_EFI:
        mount_unmount_device(local_efi_file_path, mount_directory, 'mount')
    elif image_type == SignImage.SIGN_DTB:
        mount_unmount_device(local_dtb_file_path, mount_directory, 'mount')
    else:
        raise Exception("Wrong image type is selected - Exiting the tool!")

def sign_dtb_files():
    global cmd_output

    print("Signing DTBs :: Get DTB files information...")
    if image_type == SignImage.SIGN_EFI:
        unsigned_dtb_file_path = unsigned_dtb_file_path_efi
    elif image_type == SignImage.SIGN_DTB:
        unsigned_dtb_file_path = unsigned_dtb_file_path_dtb
    else:
        raise Exception("Wrong image type is selected - Exiting the tool!")

    dtb_file_names_cmd = f"sudo ls {unsigned_dtb_file_path}"
    status = execute_command(dtb_file_names_cmd)
    if status != 0:
        #print(f"Failed to get DTB file names from {unsigned_dtb_file_path} path - Exiting the tool!")
        #sys.exit(status)
        print(f"Failed to get DTB file names from {unsigned_dtb_file_path} path - Moving on without DTB")
    else:
        print("Sign each DTB files one by one...")
        #Remove the trailing newline and split the output into a list of filenames
        dtb_file_names = cmd_output.rstrip().split('\n') #Use cmd_output from execute_command()
        if dtb_file_names is not None:
            for dtb_file in dtb_file_names:
                print(f"*****{dtb_file}*****")
                temp_mounted_dtb_file = unsigned_dtb_file_path + dtb_file
                temp_local_dtb_file = unsigned_bin_directory + dtb_file
                copy_dtb_to_local_cmd = f"sudo cp -r {temp_mounted_dtb_file} {temp_local_dtb_file}"
                print(f"Copy DTB command: {copy_dtb_to_local_cmd}...")
                status = execute_command(copy_dtb_to_local_cmd)
                if status != 0:
                    print(f"Failed to copy to {temp_local_dtb_file} - Exiting the tool!")
                    sys.exit(status)

                print(f"Changing permission to 776 for {temp_local_dtb_file}...")
                change_permission_cmd = f"sudo chmod 776 {temp_local_dtb_file}"
                status = execute_command(change_permission_cmd)
                if status != 0:
                    print(f"Failed to change permission to 776 for {temp_local_dtb_file} - Exiting the tool!")
                    sys.exit(status)
                if os.path.isfile(temp_local_dtb_file) and temp_local_dtb_file.endswith('.dtb'):
                    print(f"Signing DTB: {temp_local_dtb_file}...")
                    file_name_partition = temp_local_dtb_file.split('.')
                    file_name_partition[1] = "sig"
                    out_dtb_file = '.'.join(file_name_partition)
                    sign_dtb_cmd = f"sudo openssl cms -sign -inkey {local_key_path} -signer {local_cert_path} -binary -in {temp_local_dtb_file} --out {out_dtb_file} -outform DER"
                    print(f"Command: {sign_dtb_cmd}...")
                    status = execute_command(sign_dtb_cmd)
                    if status != 0:
                        print(f"Failed to sign {temp_local_dtb_file} - Exiting the tool!")
                        sys.exit(status)
                    print(f"Copy {out_dtb_file} to {unsigned_dtb_file_path}...")
                    copy_local_to_dtb_cmd = f"sudo cp {out_dtb_file} {unsigned_dtb_file_path}"
                    print(f"Copy DTB command: {copy_local_to_dtb_cmd}...")
                    status = execute_command(copy_local_to_dtb_cmd)
                    if status != 0:
                        print(f"Failed to copy {out_dtb_file} to {unsigned_dtb_file_path} - Exiting the tool!")
                        sys.exit(status)
                else:
                    print(f"{temp_local_dtb_file} is not a DTB file - Deleting it")
                    dlt_temp_local_dtb_cmd = f"sudo rm -rf {temp_local_dtb_file}"
                    status = execute_command(dlt_temp_local_dtb_cmd)
                    if status != 0:
                        print(f"Failed to delete {temp_local_dtb_file}")


def copy_auth_files_to_bin():
    if not os.path.isdir(loader_mount_directory):
        print(f"Directory {loader_mount_directory} does not exist!")
        print(f"Creating {loader_mount_directory}...")
        create_loader_dir_cmd = f"sudo mkdir {loader_mount_directory}"
        status = execute_command(create_loader_dir_cmd)
        if status != 0:
            print(f"Failed to create {create_loader_dir_cmd} - Exiting the tool!")
            sys.exit(status)

    print(f"Creating {keys_mount_directory}...")
    create_key_dir_cmd = f"sudo mkdir {keys_mount_directory}"
    status = execute_command(create_key_dir_cmd)
    if status != 0:
        print(f"Failed to create {keys_mount_directory} - Exiting the tool!")
        sys.exit(status)

    print(f"Creating {authkeys_mount_directory}...")
    create_auth_dir_cmd = f"sudo mkdir {authkeys_mount_directory}"
    status = execute_command(create_auth_dir_cmd)
    if status != 0:
        print(f"Failed to create {authkeys_mount_directory} - Exiting the tool!")
        sys.exit(status)

    print(f"Copying {local_pk_auth_path} to {authkeys_mount_directory}...")
    cp_pk_auth_cmd = f"sudo cp {local_pk_auth_path} {authkeys_mount_directory}"
    status = execute_command(cp_pk_auth_cmd)
    if status != 0:
        print(f"Failed to copy {local_pk_auth_path} to {authkeys_mount_directory} - Exiting the tool!")
        sys.exit(status)

    print(f"Copying {local_kek_auth_path} to {authkeys_mount_directory}...")
    cp_kek_auth_cmd = f"sudo cp {local_kek_auth_path} {authkeys_mount_directory}"
    status = execute_command(cp_kek_auth_cmd)
    if status != 0:
        print(f"Failed to copy {local_kek_auth_path} to {authkeys_mount_directory} - Exiting the tool!")
        sys.exit(status)

    print(f"Copying {local_db_auth_path} to {authkeys_mount_directory}...")
    cp_db_auth_cmd = f"sudo cp {local_db_auth_path} {authkeys_mount_directory}"
    status = execute_command(cp_db_auth_cmd)
    if status != 0:
        print(f"Failed to copy {local_db_auth_path} to {authkeys_mount_directory} - Exiting the tool!")
        sys.exit(status)

def update_conf_file(file_path, key, new_value):
    try:
        # Read the file and store lines
        with open(file_path, 'r') as file:
            lines = file.readlines()

        # Check if the key exists and remove the line if it does
        key_exists = False
        new_lines = []
        for line in lines:
            if line.startswith(key + ' '):
                key_exists = True
            else:
                new_lines.append(line)

        # Append the new key-value pair
        new_lines.append(f"{key} {new_value}\n")

        # Write the updated lines back to the file
        with open(file_path, 'w') as file:
            file.writelines(new_lines)

        return key_exists

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
        sys.exit(1)
    except IOError as e:
        print(f"Error: An I/O error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


def signing_process_cleanup():
    #Step-1: Un-mount efimountedbin
    print(f"Unmounting {mount_directory}...")
    if image_type == SignImage.SIGN_EFI:
        mount_unmount_device(local_efi_file_path, mount_directory, 'umount')
    elif image_type == SignImage.SIGN_DTB:
        mount_unmount_device(local_dtb_file_path, mount_directory, 'umount')
    else:
        raise Exception("Wrong image type is selected - Exiting the tool!")

    #Step-2: Delete efimountedbin
    print(f"Deleting {mount_directory}...")
    status = delete_directory(mount_directory)
    # dlt_mount_point_cmd = f"rm -rf {mount_directory}"
    # status = execute_command(dlt_mount_point_cmd)
    if status != 0:
        print(f"Failed to delete {mount_directory} - Exiting the tool!")
        sys.exit(status)

    #Step-3: Copy efi.bin/dtb.bin to signed_binaries directory
    print(f"Create {signed_bin_directory}...")
    create_new_directory(signed_bin_directory)

    if image_type == SignImage.SIGN_EFI:
        local_bin_file_path = local_efi_file_path
    elif image_type == SignImage.SIGN_DTB:
        local_bin_file_path = local_dtb_file_path
    else:
        raise Exception("Wrong image type is selected - Exiting the tool!")

    print(f"Copying updated {local_bin_file_path} to {signed_bin_directory}...")
    copy_signed_bin_cmd = f"cp {local_bin_file_path} {signed_bin_directory}"
    status = execute_command(copy_signed_bin_cmd)
    if status != 0:
        print(f"Failed to copy {local_bin_file_path} to {signed_bin_directory} - Exiting the tool!")
        sys.exit(status)

    #Step-4: Delete unsigned_bin_directory & keys - no need to delete this as of now
    status = delete_directory(unsigned_bin_directory)
    # print(f"Deleting {unsigned_bin_directory}...")
    # dlt_unsigned_bin_cmd = f"rm -rf {unsigned_bin_directory}"
    # status = execute_command(dlt_unsigned_bin_cmd)
    #DON'T EXIT IF FAILED - AS OUR WORK IS SUCCESSFULLY DONE IN PREVIOUS STEP
    if status != 0:
        print(f"Failed to delete {unsigned_bin_directory}. But {signed_bin_directory} has updated efi.bin/dtb.bin, please use it.")
    status = delete_directory(keys_directory)
    if status != 0:
        print(f"Failed to delete {keys_directory}. But {signed_bin_directory} has updated efi.bin/dtb.bin, please use it.")

#TODO - Before exiting in below function - make sure to do cleanup in local folder
def sign_efi_image():
    global cmd_output
    global config_status
    global config_common_loader_conf_timeout

    #Step-1: Sign bootaa64.efi image
    # Check if the bootaa64.efi file exists
    # if not os.path.isfile(unsigned_boot_img_path):
    #     print(f"'{unsigned_boot_img_path}' does not exist - Exiting the tool!")
    #     exit(1)
    print("Signing bootaa64.efi...")
    sign_boot_cmd = f"sudo sbsign --key {local_key_path} --cert {local_cert_path} {unsigned_boot_img_path} --output {signed_boot_img_path}"
    status = execute_command(sign_boot_cmd)
    if status != 0:
        print("Failed to sign bootaa64.efi - Exiting the tool!")
        sys.exit(status)

    #Step-1.1: copy signed bootaa64.efi to its original path in mount path
    print("Copy Signed bootaa64.efi to mount path...")
    copy_boot_img_cmd = f"sudo cp {signed_boot_img_path} {unsigned_boot_img_path}"
    status = execute_command(copy_boot_img_cmd)
    if status != 0:
        print("Failed to copy bootaa64.efi - Exiting the tool!")
        sys.exit(status)

    linux_image_found = False
    #Step-2: Sign Linux efi image if exists
    if os.path.exists(unsigned_linux_img_path):
        linux_img_path = next((os.path.join(unsigned_linux_img_path, f) for f in os.listdir(unsigned_linux_img_path) if f.endswith('.efi') and os.path.isfile(os.path.join(unsigned_linux_img_path, f))), None)
        if linux_img_path:
            linux_file_name = os.path.basename(linux_img_path) if linux_img_path else None
            if linux_file_name is None:
                print(f"Failed to find Linux EFI file name - Continue to check ostree path")
            else:
                linux_image_found = True

                signed_linux_img_path = unsigned_bin_directory + linux_file_name

                print(f"Signing {linux_file_name}...")
                sign_linux_img_cmd = f"sudo sbsign --key {local_key_path} --cert {local_cert_path} {linux_img_path} --output {signed_linux_img_path}"
                status = execute_command(sign_linux_img_cmd)
                if status != 0:
                    print("Failed to sign Linux EFI - Exiting the tool!")
                    sys.exit(status)

                #Step-2.1: copy signed Linux EFI to its original path in mount path
                print("Copy Signed Linux EFI to mount path...")
                copy_linux_img_cmd = f"sudo cp {signed_linux_img_path} {unsigned_linux_img_path}"
                status = execute_command(copy_linux_img_cmd)
                if status != 0:
                    print("Failed to copy Linx EFI - Exiting the tool!")
                    sys.exit(status)
        else:
            print(f"Failed to find Linux EFI file path - Continue to check ostree path!")
    else:
        print(f"Linux directory does not exists - Continue to check ostree path!")

    #Step-3: Sign vmlinuz image under ostree path
    # Check if ostree directory exists or not
    if os.path.exists(unsigned_vmlinuz_img_path):
        files_found = False
        poky_folders_found = False
        for root, dirs, files in os.walk(unsigned_vmlinuz_img_path):
            # Check if the current directory is a poky-xyz folder
            if os.path.basename(root).startswith('poky-'):
                poky_folders_found = True
                poky_folder = root
                poky_path_name = os.path.basename(root)
                print(f"Processing folder: {poky_path_name}")
                vmlinuz_files_found_in_poky = False
                for file in files:
                    if file.startswith('vmlinuz-'):
                        vmlinuz_img_path = os.path.join(root, file)
                        if not os.path.isfile(vmlinuz_img_path):
                            print(f"File does not exist or is not a file: {vmlinuz_img_path}")
                        else:
                            vmlinuz_files_found_in_poky = True
                            files_found = True
                            vmlinuz_img_name = os.path.basename(vmlinuz_img_path) if vmlinuz_img_path else None
                            if vmlinuz_img_name is None:
                                print(f"Failed to find vmlinuz file name")
                            else:
                                linux_image_found = True
                                signed_vmlinuz_img_path = unsigned_bin_directory + vmlinuz_img_name
                                print(f"Signing {vmlinuz_img_name}...")
                                sign_vmlinuz_img_cmd = f"sudo sbsign --key {local_key_path} --cert {local_cert_path} {vmlinuz_img_path} --output {signed_vmlinuz_img_path}"
                                status = execute_command(sign_vmlinuz_img_cmd)
                                if status != 0:
                                    print("Failed to sign vmlinuz - Exiting the tool!")
                                    sys.exit(status)

                                #Step-3.1: copy signed vmlinuz to its original path in mount path under poky folder
                                print("Copy Signed vmlinuz to mount path...")
                                copy_vmlinuz_img_cmd = f"sudo cp {signed_vmlinuz_img_path} {poky_folder}"
                                status = execute_command(copy_vmlinuz_img_cmd)
                                if status != 0:
                                    print("Failed to copy signed vmlinuz - Exiting the tool!")
                                    sys.exit(status)
                if not vmlinuz_files_found_in_poky:
                    print(f"No vmlinuz files found in folder: {poky_path_name}")
        if not poky_folders_found:
            print("No poky folders found under the ostree directory.")
        elif not files_found:
            print("No vmlinuz files found in any poky folders under the ostree directory.")
    else:
        print(f"The directory {unsigned_vmlinuz_img_path} does not exist.")

    if not linux_image_found:
        print("No linux image found under LINUX or ostree path - Exiting the tool!")
        sys.exit(1)

    # IMPORTANT:
    # Comment this step if efi.bin has dtb files & DO NOT have enough space to
    # store signed dtb files OR remove unwanted dtb files to sign only required
    # dtbs inside efi.bin
    #Step-3: Sign DTB files
    sign_dtb_files()

    #Step-4: Copy all auth files to efimountedbin/loader/keys/authkeys/
    copy_auth_files_to_bin()

    #Step-5: Update loader.conf file
    cp_loader_conf_cmd = f"sudo cp {loader_conf_path} {temp_loader_conf_path}"
    print(f"Copy old {loader_conf_path} to {temp_loader_conf_path} using command: {cp_loader_conf_cmd}...")
    status = execute_command(cp_loader_conf_cmd)
    if status != 0:
        print(f"Failed to copy {loader_conf_path} to {temp_loader_conf_path} - Exiting the tool!")
        sys.exit(status)

    print(f"Changing permission to 776 for {temp_loader_conf_path}...")
    change_permission_cmd = f"sudo chmod 776 {temp_loader_conf_path}"
    status = execute_command(change_permission_cmd)
    if status != 0:
        print(f"Failed to change permission to 776 for {temp_loader_conf_path} - Exiting the tool!")
        sys.exit(status)

    print("\n###################################################################")
    if config_status == 0 and config_common_loader_conf_timeout:
        #Read from config if available
        loader_conf_timeout = config_common_loader_conf_timeout
        print(f"[*****Selecting loader.conf file timeout as: {loader_conf_timeout} from config file for further operation*****]")
    else:
        #Ask user
        loader_conf_timeout = input("Enter loader.conf timeout(in secs): ")
    print("###################################################################\n")

    update_conf_file(temp_loader_conf_path, 'timeout', loader_conf_timeout)

    copy_tmp_loader_conf_cmd = f'sudo cp {temp_loader_conf_path} {loader_conf_path}'
    print(f"Copy {temp_loader_conf_path} to {loader_conf_path} using command: {copy_tmp_loader_conf_cmd}...")
    status = execute_command(copy_tmp_loader_conf_cmd)
    if status != 0:
        print(f"Failed to copy {temp_loader_conf_path} to {loader_conf_path} - Exiting the tool!")
        sys.exit(status)

    #Step-6: Un-mount efimountedbin
    signing_process_cleanup()

def sign_dtb_image():
    global cmd_output

    #Step-1: Sign DTB files
    sign_dtb_files()

    #Step-2: Copy all auth files to efimountedbin/loader/keys/authkeys/
    copy_auth_files_to_bin()

    #Step-3: Signing process cleanup
    signing_process_cleanup()

def copy_dtb_directory_data_to_combined_dtb(source_dtb_directory_path, destination_combined_dtb_file_path):
    global cmd_output

    dtb_file_names_cmd = f"sudo ls {source_dtb_directory_path}"
    print(f"Command to list files: {dtb_file_names_cmd}...")
    status = execute_command(dtb_file_names_cmd)
    if status != 0:
        print(f"Failed to get DTB file names from {source_dtb_directory_path} path - Exiting the tool!")
        sys.exit(status)
    else:
        print("Copy data from each DTB files one by one...")
        #Remove the trailing newline and split the output into a list of filenames
        dtb_file_names = cmd_output.rstrip().split('\n') #Use cmd_output from execute_command()
        if dtb_file_names is not None:
            for dtb_file in dtb_file_names:
                print(f"*****{dtb_file}*****")
                temp_mounted_dtb_file = source_dtb_directory_path + dtb_file
                if not os.path.isfile(temp_mounted_dtb_file) or not temp_mounted_dtb_file.endswith('.dtb'):
                    print(f"***** {temp_mounted_dtb_file} is either not a file or not a *.dtb file - Skip it!*****")
                    continue
                temp_local_dtb_file = unsigned_bin_directory + dtb_file
                copy_dtb_to_local_cmd = f"sudo cp {temp_mounted_dtb_file} {temp_local_dtb_file}"
                print(f"Copy DTB command: {copy_dtb_to_local_cmd}...")
                status = execute_command(copy_dtb_to_local_cmd)
                if status != 0:
                    print(f"Failed to copy to {temp_local_dtb_file} - Exiting the tool!")
                    sys.exit(status)

                print(f"Changing permission to 776 for {temp_local_dtb_file}...")
                change_permission_cmd = f"sudo chmod 776 {temp_local_dtb_file}"
                status = execute_command(change_permission_cmd)
                if status != 0:
                    print(f"Failed to change permission to 776 for {temp_local_dtb_file} - Exiting the tool!")
                    sys.exit(status)
                if os.path.isfile(temp_local_dtb_file) and temp_local_dtb_file.endswith('.dtb'):
                    print(f"Copy from DTB file: {temp_local_dtb_file} and append to {destination_combined_dtb_file_path}...")
                    try:
                        # Open the source file in read mode and destination file in append mode
                        with open(temp_local_dtb_file, 'rb') as source_file, open(destination_combined_dtb_file_path, 'ab') as destination_file:

                            # Read the contents from the source file
                            contents = source_file.read()

                            # Append the contents to the destination file
                            destination_file.write(contents)

                            print(f"Contents have been successfully copied from {temp_local_dtb_file} to {destination_combined_dtb_file_path}...")

                    except FileNotFoundError:
                        print(f"Error: The source file {temp_local_dtb_file} does not exist - Exiting the tool!")
                        exit(1)

                    except PermissionError:
                        print(f"Error: You do not have permission to read the source file or write to the destination file - Exiting the tool!")
                        exit(1)

                    except Exception as e:
                        print(f"An unexpected error occurred: {e} - Exiting the tool!")
                        exit(1)

def get_directory_size_in_bytes(directory):
    # Check if the directory exists
    if not os.path.exists(directory):
        print(f"The directory {directory} does not exist.")
        return -1
    # Check if the path is a directory
    elif not os.path.isdir(directory):
        print(f"{directory} is not a directory.")
        return -1

    total = 0
    for path, dirs, files in os.walk(directory):
        # Handle symbolic links
        if os.path.islink(path):
            print(f"{path} is a symbolic link. Skipping this directory.")
            continue
        for f in files:
            fp = os.path.join(path, f)
            try:
                total += os.path.getsize(fp)
            except PermissionError:
                # Handle permission errors
                print(f"No permission to access {fp}. Skipping this file.")
                return -1
            except OSError as e:
                # Handle other file errors
                print(f"Could not get the size of {fp}: {e}")
                return -1
            except UnicodeEncodeError:
                # Handle filenames with special characters
                print(f"Filename {fp} contains special characters. Skipping this file.")
                return -1
    return total


def combine_dtb():
    #Step-1: Initialize the Combining DTB Process
    init_dtb_combine_process()

    #Step-2: Append data from old combined-dtb.dtb from old dtb.bin
    if combine_dtb_type == CombineOperationType.CO_WITH_OLD_DTB:
        copy_dtb_directory_data_to_combined_dtb(unsigned_dtb_file_path_dtb, combined_dtb_file_name)

    #Step-3: Append data from dtb files to combined-dtb.dtb
    copy_dtb_directory_data_to_combined_dtb(dtb_files_directory, combined_dtb_file_name)

    #Step-4: Copy combined-dtb.dtb file into dtb.bin(VFAT)
    #Step-4.1: Create dtb.bin as VFAT partition & copy {combined_dtb_file_name} to it
    print(f"Create {combined_dtb_directory}...")
    create_new_directory(combined_dtb_directory)

    #Step-4.2: Get the size of combined-dtb.dtb + other files in old dtb.bin
    combine_dtb_bin_size_in_bytes = get_directory_size_in_bytes(tmp_combined_dtb_directory)
    if combine_dtb_bin_size_in_bytes == -1:
        print(f"Failed to get size of {tmp_combined_dtb_directory} - Exiting the tool!")
        exit(1)
    print(f"Size of {tmp_combined_dtb_directory} is: {combine_dtb_bin_size_in_bytes}...")

    #Step-4.3: Converting bytes to block size in multiple of 1024 and adding 512 extra blocks
    block_count_for_dtb_bin = (combine_dtb_bin_size_in_bytes//1024) + 512
    print(f"block_count_for_dtb_bin is: {block_count_for_dtb_bin}...")

    #Step-4.4: Create {combined_dtb_bin_path} as VFAT partition
    #$mkfs.vfat -C <o/p vfat filesystem file name> <no. of blocks assign to file in multiple of 1024>
    create_vfat_partition_cmd = f"mkfs.vfat -C {combined_dtb_bin_path} {block_count_for_dtb_bin}"
    print(f"Create {combined_dtb_bin_path} as VFAT partition with cmd: {create_vfat_partition_cmd}...")
    status = execute_command(create_vfat_partition_cmd)
    if status != 0:
        print(f"Failed to create {combined_dtb_bin_path} as VFAT partition - Exiting the tool!")
        sys.exit(status)

    #Step-4.5: Copy all {tmp_combined_dtb_directory} data to VFAT partition file {combined_dtb_bin_path}
    # Use glob module to expand the wildcard(*) to get all data from directory
    files_to_copy = glob.glob(os.path.join(tmp_combined_dtb_directory, '*'))

    # copy_combine_dtb_cmd = f"mcopy -i {combined_dtb_bin_path} -vsmpQ {combined_dtb_file_name} ::/"
    copy_combine_dtb_cmd = f"mcopy -i {combined_dtb_bin_path} -vsmpQ {' '.join(files_to_copy)} ::"
    print(f"Copy {tmp_combined_dtb_directory} in {combined_dtb_bin_path} with cmd: {copy_combine_dtb_cmd}...")
    status = execute_command(copy_combine_dtb_cmd)
    if status != 0:
        print(f"Failed to copy {combined_dtb_file_name} in {combined_dtb_bin_path} - Exiting the tool!")
        sys.exit(status)

    #Step-5: Cleanup
    #Step-5.1: Un-mount & Delete efimountedbin
    if combine_dtb_type == CombineOperationType.CO_WITH_OLD_DTB:
        mount_unmount_device(local_dtb_file_path, mount_directory, 'umount')
        print(f"Deleting {mount_directory}...")
        status = delete_directory(mount_directory)
        if status != 0:
            print(f"Failed to delete {mount_directory} - Exiting the tool!")
            sys.exit(status)

    #Step-5.2: Delete {tmp_combined_dtb_directory} directory
    print(f"Deleting {tmp_combined_dtb_directory}...")
    status = delete_directory(tmp_combined_dtb_directory)
    if status != 0:
        print(f"Failed to delete {mount_directory} - Exiting the tool!")
        sys.exit(status)

    #Step-5.3: Delete unsigned_bin_directory & dtb_files directory
    print(f"Deleting {unsigned_bin_directory}...")
    status = delete_directory(unsigned_bin_directory)
    if status != 0:
        print(f"Failed to delete {unsigned_bin_directory}. But {combined_dtb_bin_path} has updated dtb data, please use it.")

    print(f"Deleting {dtb_files_directory}...")
    status = delete_directory(dtb_files_directory)
    if status != 0:
        print(f"Failed to delete {dtb_files_directory}. But {combined_dtb_bin_path} has updated dtb data, please use it.")


def main():
    global os_type
    global file_path_type
    global image_type
    global operation
    global combine_dtb_type

    global config_status
    global config_common_file_path
    global config_common_image_type
    global config_common_operation
    global config_common_combine_dtb_type

    print('##### Initiating Host Tool for Signing/Combining DTB #####\n')
    # print("Python version is: " + platform.python_version())

    #Show requirement for this script
    script_prerequisite()

    """
    Step-1:
    Check python version - major version should be >= DEFINE_PYTHON_MAJOR_VER
    """
    if sys.version_info[0] < DEFINE_PYTHON_MAJOR_VER:
        raise Exception("Please use Python Version 3 - Exiting the tool!")

    # print("OS:" + os.name)
    # print("Platform.system: " + platform.system())
    # print("Platform.release: " + platform.release())
    # print("Sys.platform: " + sys.platform)

    # curr_path = os.path.abspath(__file__)
    # print ("File Path: " + curr_path)

    """
    Step-2:
    Determine the platfomr - i.e., Windows or Linux
    """
    if sys.platform.startswith('win') == True:
        print("Detected Windows system\n")
        os_type = OS_WINDOWS
    elif sys.platform.startswith('linux') == True:
        print("Detected Linux system\n")
        os_type = OS_LINUX

    #Show how to use the script
    script_usage_msg()

    #Read configuration file
    config_status = read_config()

    #Select where the required files are present - Remote or local path
    file_path_type = SelectPath.PATH_ERR
    if config_status == 0 and config_common_file_path:
        #Read from config if available
        if config_common_file_path == 'local':
            print("[*****Selecting LOCAL file path from config file for further operation*****]")
            file_path_type = SelectPath.PATH_LOCAL
        elif config_common_file_path == 'remote':
            print("[*****Selecting REMOTE file path from config file for further operation*****]")
            file_path_type = SelectPath.PATH_REMOTE
    else:
        #Ask user
        file_path_type = select_path_type()
    if file_path_type == SelectPath.PATH_ERR:
        raise Exception("Wrong path type is selected - Exiting the tool!")

    """
    Step-3:
    Select the operation - i.e., sign_image or combine_dtb
    """
    operation = SelectOperation.OP_ERR
    if config_status == 0 and config_common_operation:
        #Read from config if available
        if config_common_operation == 'sign_image':
            print("[*****Selecting IMAGE SIGNING as further operation*****]")
            operation = SelectOperation.OP_SIGN
        elif config_common_operation == 'combine_dtb':
            print("[*****Selecting COMBINING DTB as further operation*****]")
            operation = SelectOperation.OP_COMBINE_DTB
    else:
        #Ask user
        operation = select_operation_type()
    if operation == SelectOperation.OP_ERR:
        raise Exception("Wrong operation is selected - Exiting the tool!")

    """
    Step-4:
    If operation == sign_image -> Follow signing process for efi.bin/dtb.bin
    If operation == combine_dtb -> Follow combining dtb process
    """
    if operation == SelectOperation.OP_SIGN:
        """
        Step-4.1(sign_image):
        Select the image type - i.e., EFI or DTB
        """
        image_type = SignImage.SIGN_ERR
        if config_status == 0 and config_common_image_type:
            #Read from config if available
            if config_common_image_type == 'efi':
                print("[*****Selecting EFI image type from config file for further operation*****]")
                image_type = SignImage.SIGN_EFI
            elif config_common_image_type == 'dtb':
                print("[*****Selecting DTB image type from config file for further operation*****]")
                image_type = SignImage.SIGN_DTB
        else:
            #Ask user
            image_type = select_image_type()
        if image_type == SignImage.SIGN_ERR:
            raise Exception("Wrong image type is selected - Exiting the tool!")
            # print("EXIT: Invalid image type is selected for signing!")
            # return
        # elif image_type == SignImage.SIGN_EFI:
        #     print("Please provide \"efi.bin\" path")
        # elif image_type == SignImage.SIGN_DTB:
        #     print("Please provide \"dtb.bin\" path")

        """
        Step-4.2(sign_image):
        Initialize the signing process
        """
        init_signing_process()

        """
        Step-4.3(sign_image):
        Sign the image - EFI and DTB will have different process
        """
        if image_type == SignImage.SIGN_EFI:
            sign_efi_image()
        elif image_type == SignImage.SIGN_DTB:
            sign_dtb_image()
        else:
            raise Exception("Wrong image type is selected - Exiting the tool!")

        print('\n##### Host Tool Signing Process Completed #####\n')
    elif operation == SelectOperation.OP_COMBINE_DTB:
        """
        Step-4.1(combine_dtb):
        Select Which DTB combining operation will be done - i.e., combine_with_old_dtb OR combine_without_old_dtb
        """
        combine_dtb_type = CombineOperationType.CO_ERR
        if config_status == 0 and config_common_combine_dtb_type:
            #Read from config if available
            if config_common_combine_dtb_type == 'combine_with_old_dtb':
                print("[*****Selecting COMBINE WITH OLD DTB as further DTB COMBINING operation*****]")
                combine_dtb_type = CombineOperationType.CO_WITH_OLD_DTB
            elif config_common_combine_dtb_type == 'combine_without_old_dtb':
                print("[*****Selecting COMBINE WITHOUT OLD DTB as further DTB COMBINING operation*****]")
                combine_dtb_type = CombineOperationType.CO_WITHOUT_OLD_DTB
        else:
            #Ask user
            combine_dtb_type = select_combine_operation_type()
        if combine_dtb_type == CombineOperationType.CO_ERR:
            raise Exception("Wrong DTB combine operation is selected - Exiting the tool!")

        """
        Step-4.2(combine_dtb):
        Combining DTB
        """
        combine_dtb()

        print('\n##### Host Tool Combining DTB Process Completed #####\n')
    else:
        raise Exception("Wrong operation is selected - Exiting the tool!")

if __name__ == "__main__":
    main()
