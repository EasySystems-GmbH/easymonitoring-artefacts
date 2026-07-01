# Compatibility shim — canonical: ../../windows-monitor/deploy/agent-installation/publish-installer.ps1
param(
  [string]$Version = "1.7.1",
  [string]$OutputDir = ""
)
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Publish = Join-Path $Root "windows-monitor/deploy/agent-installation/publish-installer.ps1"
if (-not $OutputDir) {
  $OutputDir = Join-Path $Root "windows-monitor/publish/rollout-agent"
}
& $Publish -OutputPath $OutputDir
