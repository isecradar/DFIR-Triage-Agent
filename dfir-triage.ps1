<#
.SYNOPSIS
    Windows launcher for DFIR Triage Agent (runs inside WSL).
.DESCRIPTION
    Forwards all arguments to the WSL launcher. Windows paths (D:\Evidence\x.zip) are accepted and
    translated by the agent. Set $env:DTA_DISTRO to use a non-default WSL distribution.
.EXAMPLE
    .\dfir-triage.ps1 -i "D:\Evidence\Collection-HOST-2026-10-19T15_47_49_03_00.zip" -o "D:\Cases\IR-001"
.EXAMPLE
    .\dfir-triage.ps1 -i "D:\Evidence" -o "D:\Cases\IR-001" --workers 8
.EXAMPLE
    .\dfir-triage.ps1 --setup        # run setup.sh inside WSL
#>
$distro = if ($env:DTA_DISTRO) { @('-d', $env:DTA_DISTRO) } else { @() }
$here = (& wsl.exe @distro -e wslpath -a ($PSScriptRoot -replace '\\', '/')).Trim()
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
if ($args.Count -gt 0 -and $args[0] -eq '--setup') {
    & wsl.exe @distro -e bash "$here/setup.sh" @($args | Select-Object -Skip 1)
} else {
    & wsl.exe @distro -e "$here/dfir-triage" @args
}
exit $LASTEXITCODE
