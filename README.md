Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause-Clear

Host Signing Tool - To Sign HLOS Images
========================================

1 Introduction to the Host Signing Tool
-------------------------------------

If UEFI secure boot is enabled, then EFI & DTB images should be
signed. Signing these images manually is very lengthy and error prune
process. To automate this process - the Host signing tool should be
used.

In addition to that, this tool shall also be used to combine DTB files.

The signing tool runs on a Linux host machine(Preferred Ubuntu 18.04 or higher).
This is a command line-based python script. Using this tool, we can sign 
EFI & DTB image in two separate operations.

This script shall be invoked after the completion of the build process to sign
the compiled unsigned EFI & DTB images.

2 Overview of the Host Signing Tool
---------------------------------

This tool will run on a Linux machine with Pyhton3 installed. As
discussed earlier, this tool can either sign EFI image or DTB image in
a single operation. So, to sign both EFI & DTB images user must invoke
this tool two times with different inputs.

The host tool requires unsigned EFI or DTB
files, certificate & keys as an input. Once invoked, host tool unpacks
the unsigned image and sign items available in the package using
available key & certificate. Once signed, host tool will pack the
images again with updated items - replacing unsigned image with a
signed one.

If user wants to use this tool to combine DTB files - that should be a different
process than the signing process. User shall use this tool to combine new DTB
file with older dtb file(under dtb.bin) or create new concateneated dtb file
from available list of dtb files.

3 Working of the Host Signing Tool
--------------------------------

### 3.1 Pre-requisite to run the tool

To run this tool the host Linux machine should comply with below pre-requisites:

    1.  Install OpenSSL & sbsign utilities
    2.  Install Python3
    3.  Install these python modules
        a.  pip, subprocess, shlex, socket, glob & shutil


### 3.2 Configuration of the Host Signing Tool

User is required to configure the Host Signing Tool before starting the operation.

#### 3.2.1 Config.ini file

User can provide all the required information in ***config.ini***
configuration file and the script will read the file at the boot-up
and sign the image accordingly. Below is the list of config file
variables.

-   ***operation = sign_image or combine_dtb***(Use this config to select
    operation - 1. signing the image or 2. combining dtb)

-   ***image\_type = efi or dtb***(Use this config to select
    efi or dtb to sign separately. This option is needed if
    operation==sign_image)

-   ***combine_dtb_type = combine_with_old_dtb or combine_without_old_dtb***(Use
    this config to select which type of dtb combination operation to be done -
    1. combine with dtb from old dtb.bin or 2. Just combine set of dtb files.
    This option is needed if operation==combine_dtb)

-   ***file\_path = local or remote*** (local = keys & efi.bin/dtb.bin
    are present on the same path as the script. Remote = copy
    efi.bin/dtb.bin and keys from remote Linux machine to current path)

-   ***local\_machine\_private\_key\_path = < path of id\_rsa file in
    local machine >*** (This file shall be used to establish SSH
    connection with remote machine if ***file\_path = remote*** is
    selected)

-   ***loader\_conf\_timeout = < timeout in seconds >***(systemdboot
    wait-time to let user chose to authenticate the binaries. This
    option is required to sign efi.bin)

-   ***efi/keys/dtb/combine-dtb\_remote\_hostname = < ip or hostname of the remote
    linux machine >***(if ***file\_path = remote***, then this
    configuration is used by host tool to select the hostname of the
    remote machine to copy the efi/keys/dtb/combine-dtb file from the remote machine
    using scp.

-   ***efi/keys/dtb/combine-dtb\_remote\_username = < username\_on\_remote\_machine >*** (if ***file\_path = remote***, then this configuration is used by host tool to select the username of the remote machine to copy the efi/keys/dtb/combine-dtb file from the remote machine using scp - GIVEN THAT THE USERNAME IS CREATED ON THE LOCAL MACHINE.

-   ***efi/keys/dtb/combine-dtb\_remote\_filepath = < full\_path\_of\_file\_on\_remote\_machine >*** (if ***file\_path = remote***, then this configuration is used by host tool to select the path of the efi/key/dtb/combine-dtb file on the remote machine to copy that file from remote machine using scp.

#### 3.2.2 How to Configure using config.ini file

- User should first select which operation to be doone using -\>  ***operation*** variable. Choose either ***sign_image*** or ***combine_dtb***.

- If user selects ***operation==sign_image*** then User should select which image is to be signed using -\> ***image\_type*** variable. Choose either ***efi*** or ***dtb***.

-  User should select the location where the unsigned EFI/DTB image and
    keys-certificates are stored using ***file\_path*** variable.

    - If user choses ***local*** in the configuration file, then user will have to manually copy the EFI/DTB image and keys-certificate file in the local working directory

        - Create ***"unsigned_binaries"*** directory on the same path as the script and copy efi.bin/dtb.bin image under that directory
        - Create ***"keys"*** directory on the same path as the script and copy below files in that directory
            - db.auth, db.crt, db.key, KEK.auth, PK.auth

    - If user want script to automatically copy the required files from remote Linux machine in the same network, then user should choose ***remote*** in the configuration file.

        - User must provide information for below variables in the configuration file

            1.  ***local\_machine\_private\_key\_path*** -\> mandatory
            2.  ***\[efi\_config\]*** section -\> if ***image\_type = efi***
            3.  ***\[keys\_config\]*** section -\> mandatory
            4.  ***\[dtb\_config\]*** section -\> if ***image\_type = dtb***

        -  Please note that this script shall support copy from another linux machine only over SCP in the same network

-  Update ***loader\_conf\_timeout*** variable in the configuration
    file if ***image\_type = efi*** is selected in the configuration
    file

- If user selects ***operation==combine_dtb*** then User should select which type of DTB combination opeation to be done using -\> ***combine_dtb_type = combine_with_old_dtb or combine_without_old_dtb***.

    - If user selects ***combine_dtb_type = combine_with_old_dtb*** then Create ***"unsigned_binaries"*** directory on the same path as the script and copy dtb.bin image under that directory
    - Create ***"dtb_files"*** directory on the same path as the script and copy all the DTB files in that directory which are supposed to be combined(either with old combined dtb from dtb.bin or with each other only)

-  If user miss any of the configuration - the script shall still run
    and ask for those missing information from the user from the command
    line.

### 3.3 How to run the Host Signing Tool

1.  User should invoke the host tool after the code build process is completed and newly compiled unsigned efi.bin and dtb.bin images are available

2.  Store the Host Signing Tool files in a Host Linux machine before starting the operation. ***"signing\_tool.py"*** and ***config.ini*** files make the Host Signing Tool. Both files should be in the same working directory.

3.  Configure the Host Signing Tool as per above section.

4.  Invoke the host tool from command line using command -\> ***$python3 signing\_tool.py***

5.  Host Signing Tool will show all the user selection and operational commands on the screen while it is trying to sign the image. If something goes wrong - the tool will throw appropriate error on the command line

6.  At the end of signing process, Once the Host tool completes its process - it will store the newly signed ***efi.bin/dtb.bin*** image in a new directory called -\> ***signed\_binaries***. This will be created by the tool on the same working directory. Other directories which may be created by user during configuration will be deleted by the Host Signing Tool at the end of the signing process.

7.  Please note that this process should be followed two times to sign ***efi.bin*** and ***dtb.bin*** separately. After each process, please delete **"signed\_binaries"** directly after copying signed image before starting new operation.

8.  At the end of combining dtb process - newly created ***dtb.bin** will be available under ***unsigned\_combined\_dtb\_bin*** directory

### 3.4 Workflow of the Host Signing Tool

#### 3.4.1 Workflow-1: Signing Workflow

The Host Signing Tool takes either efi.bin or dtb.bin image &
keys-certificate as an input and signs them using a separate signing
process.

##### 3.4.1.1 Host Signing Tool Workflow

-   Host tool shall require the path of ***efi.bin & dtb.bin***(absolute
    path or network path)

    -   ***efi.bin*** contains ***Linux_Image.efi***(Linux Kernel image)
        & ***bootaa64.efi***(Bootloader image)

    -   If OSTree support is present then ***efi.bin*** contains ***vmlinuz-x.y.z*** (Linux Kernel image e.g. vmlinuz-6.6.38) under ostree directory
        & ***bootaa64.efi***(Bootloader image)

    -   ***dtb.bin*** contains ***combined-dtb.dtb***

-   Host tool shall require the path
    of ***certificate*** and ***key***(absolute path or network path) -
    which would be used to sign the images

-   Host tool can sign ***efi.bin***  with/without OSTree support as mentioned below

-   Host tool shall first mount the ***efi.bin/dtb.bin*** on FAT
    partition - which would provide below directory structure - and
    follow their separate signing process

***efi.bin*** without OSTree support
> ├── EFI
>
> │   ├── BOOT
>
> │   │   └── bootaa64.efi
>
> │   ├── Linux
>
> │   │   └── Linux_Image.efi
>
> ├── loader
>
> │   └── loader.conf

***efi.bin*** with OSTree support
> ├── EFI
>
> │   ├── BOOT
>
> │   │   └── bootaa64.efi
>
> ├── loader
>
> │   └── loader.conf
>
> ├── ostree
>
> │   ├── poky-e7a2237ecd4319dae26f498925c89d892b11e9fb0f526adce78775502550bbf8
>
> │   │   └── initramfs-6.6.38.img
>
> │   │   └── vmlinuz-6.6.38

***dtb.bin***
> └── combined-dtb.dtb
>

-   After signing the images, host tool shall copy AUTH files
    under ***/loader/keys/authkeys*** directory structure for
    both ***efi.bin*** & ***dtb.bin***. AUTH files MUST be maintained by
    user with keys & certificates and should be available for signing
    process

-   Host tool shall configure the wait-time in systemdboot loader
    configuration. This wait-time stops the kernel loading and allows
    user to review & select systemdboot menu options. This
    ***loader.conf*** file shall only be available in
    updated ***efi.bin*** file. For ***dtb.bin*** file this process
    shall not be followed

    -   Host tool shall configure ***/loader/loader.conf***

    -   Syntax for ***loader.conf***

        -   ***timeout x***

        -   x = timeout in seconds

-   After completion of image signing - host tool shall unmount
    the ***efi.bin/dtb.bin*** from FAT partition and store the
    signed ***efi.bin/dtb.bin*** on host machine on the similar path as
    Host tool under the ***signed\_binaries*** directory

-   Below is the directory structure for
    signed ***efi.bin*** & ***dtb.bin***

***efi.bin*** without OSTree support
> ├── EFI
>
> │   ├── BOOT
>
> │   │   └── bootaa64.efi
>
> │   ├── Linux
>
> │   │   └── Linux_Image.efi
>
> ├── loader
>
> │   ├── keys
>
> │   │   ├──  authkeys
>
> │   │    │    └──  db.auth
>
> │   │    │    └──  KEK.auth
>
> │   │    │    └──  PK.auth
>
> │   └── loader.conf

***efi.bin*** with OSTree support
> ├── EFI
>
> │   ├── BOOT
>
> │   │   └── bootaa64.efi
>
> ├── loader
>
> │   ├── keys
>
> │   │   ├──  authkeys
>
> │   │    │    └──  db.auth
>
> │   │    │    └──  KEK.auth
>
> │   │    │    └──  PK.auth
>
> │   └── loader.conf
>
> ├── ostree
>
> │   ├── poky-e7a2237ecd4319dae26f498925c89d892b11e9fb0f526adce78775502550bbf8
>
> │   │   └── initramfs-6.6.38.img
>
> │   │   └── vmlinuz-6.6.38

***dtb.bin***
> ├── combined-dtb.dtb
>
> ├── combined-dtb.sig
>
> ├── loader
>
> │   ├── keys
>
> │   │   ├──  authkeys
>
> │   │    │    └──  db.auth
>
> │   │    │    └──  KEK.auth
>
> │   │    │    └──  PK.auth

##### 3.4.1.2 Efi.bin signing process

-   Host tool shall use ***sbsign*** utility to
    sign ***Linux_Image.efi*** , ***vmlinuz-x.y.z *** & ***bootaa64.efi*** images separately.

-   ***sbsign*** requires ***certificate*** and ***key*** for the
    signing process. Check the following syntax where ***dsk1.key*** is
    key & ***dsk1.crt*** is certificate. Output file name is same as
    input file.

-   Example:

    -   ***sbsign --key < key file> --cert < cert file > < efi file > < o/p file location >***

    -   *sbsign \--key **dsk1.key** \--cert **dsk1.crt** bootaa64.efi bootaa64.efi*

    -   *sbsign \--key **dsk1.key** \--cert **dsk1.crt** Linux_Image.efi Linux_Image.efi*

    -   *sbsign \--key **dsk1.key** \--cert **dsk1.crt** vmlinuz-x.y.z vmlinuz-x.y.z*

##### 3.4.1.3 dtb.bin signing process


-   Host tool requires the path of the ***dtb.bin*** file

-   The host tool requires the path of ***key*** and ***certificate***
    (absolute path or network path) to sign the images.

-   UEFI secure boot requires PE format files for verification. Non-PE
    files, like ***dtb***, cannot be signed using ***sbsign*** as this
    signing tool requires PE format files as input.

-   The Host tool uses the ***openssl*** utility to sign the ***dtb***
    file. Check the following syntax where ***<u>dsk1.key</u>*** is
    key and ***<u>dsk1.crt</u>*** is certificate:

    -   *<u>openssl cms -sign -inkey < .key file > -signer < .crt file > -binary -in < dtb file > --out < O/P .sig file > -outform DER</u>*

-   Example:

    -   *openssl cms -sign -inkey dsk1.key -signer dsk1.crt -binary -in < foo.dtb file > --out < foo.sig file > -outform DER*

-   This command adds signature for dtb file in separate file (i.e.,
    foo.sig) and does not disturb original file(i.e., foo.dtb
    file). Hence, the host tool must keep both the files where the
    **\*.sign** file will be used during verification of UEFI secure
    boot process

#### 3.4.1 Workflow-2: Combining DTB Workflow

- Host tool can be used to combine the dtb files.

- Host tool requires the new dtb files to be combined under ***dtb_files/***
  directory.

- User first needs to select ***operation=combine_dtb*** from config.ini.

- User should select ***combine_dtb_type=combine_with_old_dtb*** if user wants
  to combine the available set of dtb files with the combined-dtb.dtb available
  in dtb.bin file.

  - Host tool shall require the old dtb.bin under ***unsigned_binaries/***
    directory for this particular process.

  - Host tool takes the combined-dtb.dtb from old dtb.bin and append all the dtb
    files from dtb_files/ directory to old combined-dtb.dtb.

  - After that - host tool shall create a new dtb.bin(vfat), copy all the old files/
    directories from old dtb.bin and also copy newly created combined-dtb.dtb
    with all the appended dtb files.

  - At the end, Host tool shall put the newly updated dtb.bin under
    ***unsigned_combined_dtb_bin/*** directory.

- User should select ***combine_dtb_type=combine_with_old_dtb*** if user wants
  to just combine the set of new dtb files under ***dtb_files/***.

  - Host tool takes all the dtb files from dtb_files/ directory and create a new
    combined-dtb.dtb file.

  - After that - host tool shall create a new dtb.bin(vfat) and copy newly
    created combined-dtb.dtb.

  - At the end, Host tool shall put the newly updated dtb.bin under
    ***unsigned_combined_dtb_bin/*** directory.
