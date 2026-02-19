<#
.SYNOPSIS
    Bootstrap installer for AD User Tool from GitHub Releases.

.DESCRIPTION
    Downloads the latest release of UserTool from the private GitHub repository
    using the OAuth Device Flow for authentication. Installs to C:\IT\UserTool.
    Compares release tag against local .version file - skips if already up to date.
    When versions differ, wipes the old install and does a clean extraction + full setup.

    First-run: opens a browser for GitHub authentication (device code flow).
    Subsequent runs: uses a cached token from Windows Credential Manager.

.EXAMPLE
    # One-liner install (from public repo):
    irm https://raw.githubusercontent.com/seanGSISG/UserTool-Installer/main/Install-ADUserTool.ps1 | iex

    # Or run directly if you have the script:
    .\Install-ADUserTool.ps1
#>

#Requires -Version 7.0

$ErrorActionPreference = 'Stop'

# --- Configuration ---
$GitHubOwner      = 'gsisg-inc'
$GitHubRepo       = 'UserTool'
$OAuthClientId    = 'Ov23li6evcd0dpujAjqt'
$DestPath         = 'C:\IT\UserTool'
$CredentialTarget = 'UserTool:GitHub:DeviceFlow'
$ApiBase          = 'https://api.github.com'

# --- Credential Manager helpers (via cmdkey) ---
function Get-CachedToken
{
    # Read token from Windows Credential Manager via .NET P/Invoke
    try
    {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class CredManager {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredReadW(string target, int type, int flags, out IntPtr credential);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr credential);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    public static string Read(string target) {
        IntPtr credPtr;
        if (!CredReadW(target, 1, 0, out credPtr)) return null;
        try {
            var cred = Marshal.PtrToStructure<CREDENTIAL>(credPtr);
            if (cred.CredentialBlobSize > 0) {
                return Marshal.PtrToStringUni(cred.CredentialBlob, cred.CredentialBlobSize / 2);
            }
            return null;
        } finally { CredFree(credPtr); }
    }
}
"@ -ErrorAction SilentlyContinue
        return [CredManager]::Read($CredentialTarget)
    } catch
    {
        return $null
    }
}

function Save-CachedToken
{
    param([string]$Token)

    # Store as a generic credential via cmdkey
    $null = cmdkey /generic:$CredentialTarget /user:oauth /pass:$Token 2>&1
}

function Remove-CachedToken
{
    $null = cmdkey /delete:$CredentialTarget 2>&1
}

# --- GitHub API helpers ---
function Test-GitHubToken
{
    param([string]$Token)

    try
    {
        $headers = @{
            Authorization           = "Bearer $Token"
            Accept                  = 'application/vnd.github+json'
            'X-GitHub-Api-Version'  = '2022-11-28'
        }
        $null = Invoke-RestMethod -Uri "$ApiBase/user" -Headers $headers -ErrorAction Stop
        return $true
    } catch
    {
        return $false
    }
}

function Invoke-DeviceFlow
{
    # Step 1: Request device and user verification codes
    $body = @{
        client_id = $OAuthClientId
        scope     = 'repo'
    }
    $headers = @{ Accept = 'application/json' }

    $deviceResponse = Invoke-RestMethod -Uri 'https://github.com/login/device/code' `
        -Method Post -Body $body -Headers $headers

    $deviceCode   = $deviceResponse.device_code
    $userCode     = $deviceResponse.user_code
    $verifyUri    = $deviceResponse.verification_uri
    $expiresIn    = $deviceResponse.expires_in
    $interval     = $deviceResponse.interval

    # Step 2: Prompt user
    Write-Host "`n  GitHub Authentication Required" -ForegroundColor Cyan
    Write-Host "  ==============================" -ForegroundColor Cyan
    Write-Host "`n  1. A browser will open to: $verifyUri" -ForegroundColor Yellow
    Write-Host "  2. Enter this code:  " -NoNewline -ForegroundColor Yellow
    Write-Host $userCode -ForegroundColor White -BackgroundColor DarkBlue
    Write-Host ""

    # Copy code to clipboard and open browser
    Set-Clipboard -Value $userCode
    Write-Host "  (Code copied to clipboard)" -ForegroundColor Gray
    Start-Process $verifyUri

    # Step 3: Poll for access token
    $deadline = (Get-Date).AddSeconds($expiresIn)
    $tokenBody = @{
        client_id   = $OAuthClientId
        device_code = $deviceCode
        grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
    }

    Write-Host "  Waiting for authorization..." -ForegroundColor Gray -NoNewline

    while ((Get-Date) -lt $deadline)
    {
        Start-Sleep -Seconds $interval

        try
        {
            $tokenResponse = Invoke-RestMethod -Uri 'https://github.com/login/oauth/access_token' `
                -Method Post -Body $tokenBody -Headers $headers -ErrorAction Stop

            if ($tokenResponse.access_token)
            {
                Write-Host " Authorized!" -ForegroundColor Green
                return $tokenResponse.access_token
            }

            # Handle pending/slow_down responses
            if ($tokenResponse.error -eq 'slow_down')
            {
                $interval = $tokenResponse.interval
            } elseif ($tokenResponse.error -eq 'authorization_pending')
            {
                Write-Host "." -NoNewline -ForegroundColor Gray
            } elseif ($tokenResponse.error -eq 'expired_token')
            {
                Write-Host ""
                throw "Device code expired. Please run the installer again."
            } elseif ($tokenResponse.error -eq 'access_denied')
            {
                Write-Host ""
                throw "Authorization was denied."
            } elseif ($tokenResponse.error)
            {
                Write-Host ""
                throw "OAuth error: $($tokenResponse.error) - $($tokenResponse.error_description)"
            }
        } catch
        {
            Write-Host "." -NoNewline -ForegroundColor Gray
        }
    }

    Write-Host ""
    throw "Authorization timed out. Please run the installer again."
}

function Get-GitHubToken
{
    # Try cached token first
    $cached = Get-CachedToken
    if ($cached -and (Test-GitHubToken $cached))
    {
        return $cached
    }

    # Cached token missing or expired — run device flow
    if ($cached)
    {
        Write-Host "Cached GitHub token expired, re-authenticating..." -ForegroundColor Yellow
        Remove-CachedToken
    }

    $token = Invoke-DeviceFlow
    Save-CachedToken $token
    return $token
}

function Get-LatestRelease
{
    param([string]$Token)

    $headers = @{
        Authorization           = "Bearer $Token"
        Accept                  = 'application/vnd.github+json'
        'X-GitHub-Api-Version'  = '2022-11-28'
    }

    $release = Invoke-RestMethod -Uri "$ApiBase/repos/$GitHubOwner/$GitHubRepo/releases/latest" -Headers $headers
    return $release
}

function Install-ReleaseAsset
{
    param(
        [string]$Token,
        [object]$Release
    )

    # Find the zip asset
    $asset = $release.assets | Where-Object { $_.name -match '\.zip$' } | Select-Object -First 1
    if (-not $asset)
    {
        throw "No zip asset found in release $($release.tag_name)"
    }

    # Download the asset
    $tempZip = Join-Path $env:TEMP $asset.name
    $headers = @{
        Authorization           = "Bearer $Token"
        Accept                  = 'application/octet-stream'
        'X-GitHub-Api-Version'  = '2022-11-28'
    }

    Write-Host "Downloading $($asset.name)..." -ForegroundColor Gray
    Invoke-WebRequest -Uri "$ApiBase/repos/$GitHubOwner/$GitHubRepo/releases/assets/$($asset.id)" `
        -Headers $headers -OutFile $tempZip

    # Create parent directory if needed
    $parentDir = Split-Path $DestPath -Parent
    if (-not (Test-Path $parentDir))
    {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        Write-Host "Created $parentDir" -ForegroundColor Gray
    }

    # Wipe existing install for a clean extraction
    if (Test-Path $DestPath)
    {
        Write-Host "Removing old installation..." -ForegroundColor Gray
        Remove-Item -Path $DestPath -Recurse -Force
    }

    # Extract
    Write-Host "Extracting to $DestPath..." -ForegroundColor Gray
    New-Item -ItemType Directory -Path $DestPath -Force | Out-Null
    Expand-Archive -Path $tempZip -DestinationPath $DestPath -Force

    # Clean up temp file
    Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue

    # Write version file
    $Release.tag_name | Set-Content -Path (Join-Path $DestPath '.version') -Encoding UTF8

    Write-Host "Files extracted to $DestPath" -ForegroundColor Green

    # Unblock all scripts
    $blockedFiles = Get-ChildItem -Path $DestPath -Recurse -Include *.ps1, *.psm1, *.psd1
    $count = ($blockedFiles | Measure-Object).Count
    if ($count -gt 0)
    {
        $blockedFiles | Unblock-File
        Write-Host "Unblocked $count script file(s)" -ForegroundColor Green
    }
}

# --- Main ---
try
{
    Write-Host "`n=== AD User Tool Installer ===" -ForegroundColor Cyan
    Write-Host "Source: github.com/$GitHubOwner/$GitHubRepo" -ForegroundColor Gray

    # Authenticate
    $token = Get-GitHubToken

    # Get latest release info
    $release = Get-LatestRelease $token
    $remoteVersion = $release.tag_name

    # Check local version
    $versionFile = Join-Path $DestPath '.version'
    $localVersion = $null
    if (Test-Path $versionFile)
    {
        $localVersion = (Get-Content $versionFile -Raw).Trim()
    }

    $isUpdate = Test-Path $DestPath

    if ($isUpdate -and $localVersion -and ($localVersion -eq $remoteVersion))
    {
        Write-Host "AD User Tool is already up to date ($remoteVersion)" -ForegroundColor Green
        Write-Host ""
        for ($i = 5; $i -ge 1; $i--)
        {
            Write-Host "`rClosing in $i..." -NoNewline -ForegroundColor Gray
            Start-Sleep -Seconds 1
        }
        return
    }

    if ($isUpdate)
    {
        Write-Host "Updating: $localVersion -> $remoteVersion" -ForegroundColor Yellow
    } else
    {
        Write-Host "Fresh install: $remoteVersion" -ForegroundColor Yellow
    }

    # Download and install
    Install-ReleaseAsset -Token $token -Release $release

    # Run full setup
    Write-Host "`nRunning setup..." -ForegroundColor Yellow
    & "$DestPath\Setup-ADUserTool.ps1"
} catch
{
    Write-Host "`nInstaller error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Run the command again or check https://github.com/gsisg-inc/UserTool/issues" -ForegroundColor Gray
}
