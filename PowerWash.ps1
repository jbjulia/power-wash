<#
This is an automated script to free up disk space and securely overwrite deleted files. Please make sure you have
closed out all other programs and files before using this script. Please note: ONLY deleted file memory will be
overwritten if desired, not ALL free space on disk. Please review the README before continuing.
#>

param([switch]$Elevated)
function Test-Admin
{
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent() )
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)
{
    if ($elevated)
    {
        # Tried to elevate, did not work, aborting
    }
    else
    {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
        Stop-Process -Id $PID
    }
    exit
}

function DeleteComputerRestorePoints
{
    [CmdletBinding(SupportsShouldProcess = $True)]param(
        [Parameter(
                Position = 0,
                Mandatory = $true,
                ValueFromPipeline = $true
        )]
        $restorePoints
    )
    begin {
        Write-Host "Deleting System Restore Points" -Foreground Yellow
        $fullName = "SystemRestore.DeleteRestorePoint"
        $isLoaded = $null -ne ([AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetTypes() } | Where-Object { $_.FullName -eq $fullName })
        if (!$isLoaded)
        {
            $SRClient = Add-Type   -memberDefinition  @"
		    	[DllImport ("Srclient.dll")]
		        public static extern int SRRemoveRestorePoint (int index);
"@  -Name DeleteRestorePoint -NameSpace SystemRestore -PassThru
        }
    }
    process {
        foreach ($restorePoint in $restorePoints)
        {
            if ( $PSCmdlet.ShouldProcess("$( $restorePoint.Description )", "Deleting Restore Point"))
            {
                [SystemRestore.DeleteRestorePoint]::SRRemoveRestorePoint($restorePoint.SequenceNumber)
            }
        }
    }
}

function CleanFolders
{
    Write-Host "Cleaning Folders" -Foreground Yellow
    if (Test-Path C:\Config.Msi)
    {
        Remove-Item -Path C:\Config.Msi -Force -Recurse -ErrorAction SilentlyContinue
    }
    if (Test-Path C:\Intel)
    {
        Remove-Item -Path C:\Intel -Force -Recurse -ErrorAction SilentlyContinue
    }
    if (Test-Path C:\PerfLogs)
    {
        Remove-Item -Path C:\PerfLogs -Force -Recurse -ErrorAction SilentlyContinue
    }
    if (Test-Path $env:windir\memory.dmp)
    {
        Remove-Item $env:windir\memory.dmp -Force -ErrorAction SilentlyContinue
    }
}

function DeleteWindowsErrorFiles
{
    Write-Host "Deleting Windows Error Reporting Files" -Foreground Yellow
    if (Test-Path C:\ProgramData\Microsoft\Windows\WER)
    {
        Get-ChildItem -Path C:\ProgramData\Microsoft\Windows\WER -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
}

function RemoveTempFiles
{
    Write-Host "Removing Temp Files" -Foreground Yellow
    Remove-Item -Path "$env:windir\Temp\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:windir\minidump\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:windir\Prefetch\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Users\*\AppData\Local\Temp\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\WER\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatCache\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\IECompatUaCache\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\IEDownloadHistory\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies\*" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
}

function RemoveWindowsUpdateDownloads
{
    Write-Host "Removing Windows Update Downloads" -Foreground Yellow
    Stop-Service wuauserv -Force # -Verbose
    Stop-Service TrustedInstaller -Force # -Verbose
    Remove-Item -Path "$env:windir\SoftwareDistribution\*" -Force -Recurse
    Remove-Item $env:windir\Logs\CBS\* -Force -Recurse
    Start-Service wuauserv # -Verbose
    Start-Service TrustedInstaller # -Verbose
}

function CheckWindowsCleanup
{
    Write-Host "Checking Windows Cleanup Manager Exists" -Foreground Yellow
    if (!(Test-Path C:\windows\System32\cleanmgr.exe))
    {
        Write-Warning "Not Found: Windows Cleanup Manager is now installing"
        Copy-Item $env:windir\winsxs\amd64_microsoft-windows-cleanmgr_31bf3856ad364e35_6.1.7600.16385_none_c9392808773cd7da\cleanmgr.exe $env:windir\System32
        Copy-Item $env:windir\winsxs\amd64_microsoft-windows-cleanmgr.resources_31bf3856ad364e35_6.1.7600.16385_en-us_b9cb6194b257cc63\cleanmgr.exe.mui $env:windir\System32\en-US
    }
}

function RunWindowsCleanup
{
    if (-not(Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders' -Name $StateFlags))
    {
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\BranchCache' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Offline Pages Files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Memory Dump Files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Service Pack Cleanup' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Upgrade Discarded Files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\User file versions' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Archive Files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Queue Files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting System Archive Files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting System Queue Files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Temp Files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows ESD installation files' -Name $StateFlags -Type DWORD -Value 2
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Log Files' -Name $StateFlags -Type DWORD -Value 2
    }
}

function RunDiskCleanup
{
    Write-Host "Running Windows Disk Cleanup" -Foreground Yellow
    Start-Process -FilePath CleanMgr.exe -ArgumentList $StateRun  -WindowStyle Hidden -Wait
}

function ClearEventLogs
{
    Write-Host "Clearing All Event Logs" -Foreground Yellow
    wevtutil el | Foreach-Object { wevtutil cl "$_" } # { Write-Host "Clearing $_"; wevtutil cl "$_" }
}

function EmptyRecycleBin
{
    Write-Host "Emptying Recycle Bin" -Foreground Yellow
    Clear-RecycleBin -Force # Clear contents of ALL Recycle Bins
}

function OverwriteDeletedFiles
{
    Write-Host "Would you like to overwite all deleted files? (Default is No)" -Foreground Green
    $ReadHost = Read-Host " ( y / n ) "
    switch ($ReadHost)
    {
        Y {
            Write-Host "Overwriting Free Space..." -Foreground Yellow
            Cipher /w:C: # Securely overwrite ONLY deleted files
        }
        N {
            Write-Host("Skipping file overwrite") -Foreground Red
        }
        Default {
            Write-Host("Skipping file overwrite") -Foreground Red
        }
    }
    if (Test-Path C:\EFSTMPWP)
    {
        Remove-Item -Path C:\EFSTMPWP -Force -Recurse -ErrorAction SilentlyContinue
    }
}

function GetFreeSpace
{
    Write-Host "Disk Usage before and after cleanup" -Foreground Green
    $FreeSpaceAfter = (Get-WmiObject win32_logicaldisk -Filter "DeviceID='C:'" | Select-Object Freespace).FreeSpace / 1GB
    "-------------------------------------------------------------------------------------------------------------"
    "Free Space Before:     {0:0.##}" -f $FreeSpaceBefore
    "Free Space After:      {0:0.##}" -f $FreeSpaceAfter
    "-------------------------------------------------------------------------------------------------------------"
}

Write-Host "You are about to Power Wash your computer, do you wish to proceed? (Default is Yes)" -Foreground Green
$ReadHost = Read-Host " ( y / n ) "
switch ($ReadHost)
{
    Y {
        $FreeSpaceBefore = (Get-WmiObject win32_logicaldisk -Filter "DeviceID='C:'" | Select-Object Freespace).FreeSpace / 1GB
        $StateFlags = 'StateFlags0013' # Set StateFlags setting for each item in Windows Disk Cleanup Utility
        $StateRun = $StateFlags.Substring($StateFlags.get_Length() - 2)
        $StateRun = '/sagerun:' + $StateRun

        Get-ComputerRestorePoint | DeleteComputerRestorePoints # -WhatIf
        CleanFolders
        DeleteWindowsErrorFiles
        RemoveTempFiles
        RemoveWindowsUpdateDownloads
        CheckWindowsCleanup
        RunWindowsCleanup
        RunDiskCleanup
        ClearEventLogs
        EmptyRecycleBin
        OverwriteDeletedFiles
        GetFreeSpace
    }
    N {
        exit
    }
}