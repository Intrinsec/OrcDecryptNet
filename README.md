# OrcDecryptNet

## Info

OrcDecryptNet is a .NET implementation of the official Python script https://github.com/DFIR-ORC/orc-decrypt provided by ANSSI, focused on decrypting DFIR-ORC archives in .p7b format. OrcDecryptNet is compatible with all platforms that support the .NET 8.0 framework.


**New Features:**
- **Windows DPAPI Credential Storage**: Securely store private keys and passwords on Windows
- **Simplified Usage**: Decrypt archives with just the file path after initial setup
- **Automatic Output Path**: Default output to the same directory as the archive
- **Comprehensive Help**: Built-in help system with `-h/--help`

## Build

* Install Visual Studio 2022 for .NET development.
* Ensure that the .NET 8.0 SDK is installed.
* Install the required NuGet dependencies.
* Build in x64 Release mode with Visual Studio.

## Usage

**Ensure that the .NET >= 8.0 runtime is installed.**
**The private key must be in PFX (PKCS#12) format.**

### Quick Start (Windows with DPAPI)

1. **First-time setup** - Store your credentials securely:
```bash
OrcDecryptNet --setup C:\path\to\private.pfx [password]
```

2. **Decrypt archives** - Just provide the archive path:
```bash
OrcDecryptNet archive.p7b
```

### Manual Mode (All Platforms)

```bash
OrcDecryptNet <archive_path> <output_folder> <private_key.pfx> [password] [-v|--verbose]
```

### Help and Options

```bash
OrcDecryptNet --help           # Show detailed help
OrcDecryptNet -h               # Short help
OrcDecryptNet --clear-credentials  # Remove stored credentials
```

### Examples

**Setup credentials (Windows):**
```bash
OrcDecryptNet --setup C:\Keys\private.pfx mypassword
```

**Simple decryption with stored credentials:**
```bash
OrcDecryptNet C:\Data\archive.p7b
OrcDecryptNet C:\Data\archive.p7b C:\Output\
```

**Manual decryption:**
```bash
dotnet OrcDecryptNet.dll /mnt/e/SuperCase/ORC/01-ORC-raw/dfir-orc_archive.7z.p7b /mnt/e/SuperCase/ORC/02-ORC-decrypted/ key.pfx SuperPassphrase -v
OrcDecryptNet.exe E:\SuperCase\ORC\01-ORC-raw\dfir-orc_archive.7z.p7b E:\SuperCase\ORC\02-ORC-decrypted\ key.pfx SuperPassphrase -v
```

**Verbose logging:**
```bash
OrcDecryptNet archive.p7b --verbose
OrcDecryptNet --setup key.pfx password -v
```

## Security Notes

- **Windows DPAPI**: Credentials are encrypted using Windows Data Protection API and tied to your user account
- **Cross-platform**: Manual mode works on all platforms supporting .NET 8.0
- **No credential storage**: On non-Windows platforms, credentials must be provided each time
