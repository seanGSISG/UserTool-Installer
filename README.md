# AD User Tool — Installer

Bootstrap installer for the [AD User Tool](https://github.com/gsisg-inc/UserTool) (private repo). Downloads the latest release from GitHub using OAuth Device Flow authentication.

## Install

Paste in PowerShell 7:

```powershell
irm https://raw.githubusercontent.com/seanGSISG/UserTool-Installer/main/Install-ADUserTool.ps1 | iex
```

## What Happens

1. **First run** — A browser opens to `https://github.com/login/device`. Sign in with your GitHub account and enter the code shown in the terminal (auto-copied to clipboard).
2. **Download** — The latest release zip is downloaded from `gsisg-inc/UserTool` and extracted to `C:\IT\UserTool`.
3. **Setup** — Dependencies are installed (gsudo, RSAT AD tools, Microsoft Graph modules) and a Windows Terminal profile is configured.
4. **Future runs** — Your token is cached in Windows Credential Manager. The installer checks the version and only updates when a new release is available.

## Requirements

- **PowerShell 7+** — [Download](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows)
- **GitHub account** with access to the `gsisg-inc` organization

## Troubleshooting

### Clear cached token

If authentication fails or your token has expired:

```powershell
cmdkey /delete:UserTool:GitHub:DeviceFlow
```

Then re-run the install command.

### "Organization has enabled OAuth App access restrictions"

Your GitHub account must be a member of the `gsisg-inc` org. Contact an org admin to confirm your membership.
