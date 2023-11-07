###################################################################################################
#
# File: fimon.ps1
#
# Description:
#     File Integrity Monitoring on Windows servers
#     Script includes embedded webhooks to an Event Mgmt tool for state based events triggers including reset event
#
# Usage: PowerShell .\fimon_main.bat
#
# IMPORTANT: Users are NOT required to update or make changes to the script fimon.ps1
# IMPORTANT: Users are ONLY required to make updates to the config file fimon_config.json
#
###################################################################################################

param(
    [string] $DateTime,
    [string] $OutFile = $null
)
$Start = Get-Date -UFormat %s

###################################################################################################
#
# Parsing JSON data
#
###################################################################################################

$ConfigFile = "$pwd\fimon_config.json"
$Config = Get-Content -Raw -Path $ConfigFile | ConvertFrom-Json
$Config_application = $Config.application
$Config_severity = $Config.severity
$Config_domain = (Get-WmiObject Win32_ComputerSystem).Name
$Config_autoincident = $Config.autoincident
$Config_workgroup = $Config.workgroup
$Config_core_api_token_key = $Config.core_api_token_key
$Config_core_api_token_value = $Config.core_api_token_value
$Config_core_endpoint = $Config.core_endpoint
$Config_is_dmz = $Config.is_dmz
$Config_dmz_endpoint = $Config.dmz_endpoint
$Config_is_external = $Config.is_external
$Config_ext_endpoint = $Config.ext_endpoint
$Config_ext_api_token_key = $Config.ext_api_token_key
$Config_ext_api_token_value = $Config.ext_api_token_value
$Config_ext_oauth_token = $Config.ext_oauth_token
$Config_event_query = $Config.event_query
$Config_event_oauth_token = $Config.event_oauth_token
$Config_telemetry_token = $Config.telemetry_token
$Config_telemetry_endpoint = $Config.telemetry_endpoint
$Config_continuous_change = $Config.continuous_change
$Config_results = $Config.results
$Config_targets = $Config.targets
$Config_exclude = @($Config.exclude)

$BaselineFile = "$pwd\fimon_baseline.json"
$AuditResults = "$Config_results\fimon_$DateTime.zip"
$Exclusions = "$AuditResults\fimon_exclusions_$DateTime.csv"
$Violations = "$AuditResults\fimon_violations_$DateTime.csv"

"Application Name:     $Config_application"
"Config File:          $ConfigFile"
"Baseline File:        $BaselineFile"
"Audit Results Folder: $AuditResults`n"
foreach ($Target in $Config_targets) { "Target: $Target" }
"Excluded Filetypes: $Config_exclude"

# Current inventory found during the current audit. This becomes the baseline for the next audit.
$Inventory = @{ }

# Contains our baseline for files and checksums
$Baseline = @{ }

# Array containing all of the audit exceptions (files added, deleted, modified) during the audit
$Exceptions = New-Object System.Collections.ArrayList

# Contains files facing Get-FileHash errors
$FailedFiles = New-Object System.Collections.ArrayList
$FailedFilesTemp = New-Object System.Collections.ArrayList

# Creating global counter variables for Grafana data
$NoAccess = 0
$Changed = 0
$Missing = 0
$New = 0

###################################################################################################
#
# Creating the Audit Results Folder
#
###################################################################################################

# Add $OutFile to $AuditResults in second run
if ($OutFile) {
    if (Test-Path $OutFile) {
        try {
            Compress-Archive -Path $OutFile -Update -DestinationPath $AuditResults -ErrorAction Stop
            "`nAdded $OutFile to $AuditResults"
        }
        catch {
            "ERROR5: Failed to create Results folder. $_"
        }
    }
    else {
        "ERROR6: Did not find file $OutFile"
    }
    exit
}

# Function to group files for current run into a single folder
function ArchiveFiles() {
    $ErrorFlag = 0
    if (Test-Path $ConfigFile) {
        try {
            Compress-Archive -Path $ConfigFile -Update -DestinationPath $AuditResults -ErrorAction Stop
        }
        catch {
            "ERROR1: Failed to create Results folder. $_"
        }
    }
    if (Test-Path $BaselineFile) {
        try {
            Compress-Archive -Path $BaselineFile -Update -DestinationPath $AuditResults -ErrorAction Stop
        }
        catch {
            "ERROR2: Failed to create Results folder. $_"
        }
    }
    if (Test-Path $Exclusions) {
        try {
            Compress-Archive -Path $Exclusions -Update -DestinationPath $AuditResults -ErrorAction Stop
        }
        catch {
            "ERROR3: Failed to create Results folder. $_"
            $ErrorFlag = 1
        }
        if ($ErrorFlag -eq 0) {
            Remove-Item -Path $Exclusions -Force
        }
    }
    if (Test-Path $Violations) {
        try {
            Compress-Archive -Path $Violations -Update -DestinationPath $AuditResults -ErrorAction Stop
        }
        catch {
            "ERROR4: Failed to create Results folder. $_"
            $ErrorFlag = 1
        }
        if ($ErrorFlag -eq 0) {
            Remove-Item -Path $Violations -Force
        }
    }
}

###################################################################################################
#
# Webhook to Event Management tool with Notify and Auto-Ticketing
#
###################################################################################################

function WebhookCall($sev, $title) {
    $PayloadEvent = @{
        application = $Config_application
        object      = 'File Integrity Monitor'
        category    = 'Compliance'
        severity    = $Config_severity
        domain      = $Config_domain
        title       = $title
        origin      = 'windows_fimon'
        stateful    = 'true'
    }

    if ($Config_autoincident -eq "true") {
        $Incident = @{ workgroup = $Config_workgroup }
        $Body = @{
            event    = $PayloadEvent
            incident = $Incident
        }
    }
    else {
        $Body = @{ event = $PayloadEvent }
    }

    if ($Config_is_dmz -eq "true") {
        $Body[$Config_ext_api_token_key] = $Config_ext_api_token_value
        $Params = @{
            Uri     = $Config_dmz_endpoint
            Headers = @{ Authorization = $Config_ext_oauth_token }
        }
    }
    elseif ($Config_is_external -eq "true") {
        $Body[$Config_ext_api_token_key] = $Config_ext_api_token_value
        $Params = @{
            Uri     = $Config_ext_endpoint
            Headers = @{ Authorization = $Config_ext_oauth_token }
        }
    }
    else {
        $Body[$Config_core_api_token_key] = $Config_core_api_token_value
        $Params = @{
            Uri = $Config_core_endpoint
        }
    }

    $Body = $Body | ConvertTo-Json
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    Invoke-RestMethod -Method 'POST' @Params -Body $Body -ContentType 'application/json' -ErrorAction SilentlyContinue -ErrorVariable RestError
    if ($RestError) {
        $HttpStatusCode = $RestError.ErrorRecord.Exception.Response.StatusCode.value__
        $HttpStatusDescription = $RestError.ErrorRecord.Exception.Response.StatusDescription
        "Http Status Code: $($HttpStatusCode) Http Status Description: $($HttpStatusDescription)"
    }
}

function CheckWebhookCall() {
    "`nRunning the Monitor-the-Monitor check."
    Start-Sleep -Seconds 60
    $Uri = $Config_event_query
    $Header = @{ Authorization = $Config_event_oauth_token }
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    $Result = Invoke-RestMethod -Method 'GET' -Uri $Uri -Headers $Header -ErrorAction SilentlyContinue -ErrorVariable RestError
    if ($RestError) {
        $HttpStatusCode = $RestError.ErrorRecord.Exception.Response.StatusCode.value__
        $HttpStatusDescription = $RestError.ErrorRecord.Exception.Response.StatusDescription
        "Http Status Code: $($HttpStatusCode) Http Status Description: $($HttpStatusDescription)"
    }

    if (!$Result.result) {
        $StopLoop = $false
        $RetryCount = 1
        do {
            if ($RetryCount -gt 3) {
                "`nWebhook call failed after 3 retries."
                $StopLoop = $true
            }
            else {
                "`nWebhook call failed, retrying in 60s. Retry count: $RetryCount"
                Start-Sleep -Seconds 60
                SendEvent
                $RetryCount++
            }
        } while ($StopLoop -eq $false)
    }
    else {
        "Webhook event found."
    }
}

function GrafanaCall {
    $Header = @{ TELEMETRY_INGRESSION_TOKEN = $Config_telemetry_token }
    $Body = "fimon_metrics noaccess=$NoAccess,changed=$Changed,missing=$Missing,new=$New"
    Invoke-WebRequest -UseBasicParsing -Uri $Config_telemetry_endpoint -Headers $Header -Method 'POST' -Body $Body
}

###################################################################################################
#
# File Integrity Monitoring and State based event trigger
#
###################################################################################################

function SendEvent() {
    if ($Config_continuous_change -eq "true") {
        $TouchFile = "$pwd\fimon"
        if ($Exceptions.count -ge 1) {
            if (Test-Path -Path $TouchFile -PathType leaf) {
                "File Integrity state changed to normal. Generating reset event."
                Remove-Item $TouchFile
                $Config_severity = "normal"
                $title = "Generated reset event. File Integrity Monitor detected changes. Audit Results Folder: $AuditResults"
            }
        }
        else {
            if (Test-Path $AuditResults) {
                $null >> $TouchFile
                $title = "FAILED: File Integrity Monitor detected no changes. Audit Results Folder: $AuditResults"
            }
            else {
                $null >> $TouchFile
                $title = "FAILED: File Integrity Monitor detected no changes. Audit Results Folder: $Config_results"
            }
        }
    }
    else {
        if ($Exceptions.Count -eq 0) {
            $Config_severity = "normal"
            $title = "SUCCESS: File Integrity Monitor detected no changes. Audit Results Folder: $AuditResults"
        }
        else {
            if (Test-Path $AuditResults) {
                $title = "FAILED: File Integrity Monitor detected changes. Audit Results Folder: $AuditResults"
            }
            else {
                $title = "FAILED: File Integrity Monitor detected changes. Audit Results Folder: $Config_results"
            }
        }
    }
    "`nSeverity: $Config_severity`n$title"
    WebhookCall $Config_severity $title
}

function ProcessTarget() {
    foreach ($Target in $Config_targets) {
        try {
            "`nFetching inventory from: $Target"
            $Start = Get-Date -UFormat %s
            $Files = Get-ChildItem -Path $Target -Exclude $Config_exclude -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable MyErrors | Select-Object -ExpandProperty Fullname
            foreach ($Incidence in $MyErrors) {
                $Exceptions.Add("UNABLE TO ACCESS TARGET: " + $Incidence.CategoryInfo.TargetName) > $null
                $Global:NoAccess++
            }
            foreach ($File in $Files) {
                if (Test-Path $File -PathType Container) {
                    $Inventory[$File] = $null
                }
                else {
                    $Hash = Get-FileHash -Path $File -Algorithm MD5 -ErrorAction SilentlyContinue -ErrorVariable MyErrors
                    foreach ($Incidence in $MyErrors) {
                        Get-Date -UFormat %c
                        $FailedFiles.Add("$File") > $null
                    }
                    $Inventory[$File] = $Hash.Hash
                }
            }
            $Inventory[$Target] = $null
            # Save list of files excluded from audit to $Exclusions file
            Get-ChildItem -Path $Target -Include $Config_exclude -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Fullname >> $Exclusions
            "Complete. Processing time: $((Get-Date -UFormat %s) - $Start)"
        }
        catch {
            "ERROR: Exception processing '$Target'. $_"
        }
    }
}

function ProcessFailedFiles() {
    $RetryCount = 1
    while ($FailedFiles.Count -gt 0) {
        if ($RetryCount -gt 3) {
            "`nGenerating FileHash failed after 3 retries."
            $FailedFiles.Clear()
        }
        else {
            "`nGenerating FileHash failed, retrying in 60s. Retry count: $RetryCount"
            Start-Sleep -Seconds 60
            $FailedFilesTemp = $($FailedFiles)
            $FailedFiles.Clear()
            foreach ($File in $FailedFilesTemp) {
                $Hash = Get-FileHash -Path $File -Algorithm MD5 -ErrorAction SilentlyContinue -ErrorVariable MyErrors
                foreach ($Incidence in $MyErrors) {
                    Get-Date -UFormat %c
                    $FailedFiles.Add("$File") > $null
                }
                $Inventory[$File] = $Hash.Hash
            }
            $RetryCount++
        }
    }
}

function IntegrityCheck() {
    # Load the existing baseline and convert to a Hash. Some versions of PS doesn't support 'ConvertFrom-Json -AsHashtable'.
    if (Test-Path $BaselineFile) {
        "`nPerforming Integrity Check against Baseline file. Looking for CHANGED, MISSING, or NEW files."
        $Lines = (Get-Content -Raw -Path $BaselineFile | ConvertFrom-Json).psobject.properties
        foreach ($Line in $Lines) {
            $Baseline[$Line.Name] = $Line.Value
        }
    }
    else {
        "`nInitial run. Creating Baseline file."
    }

    # Save the current inventory as the new baseline
    $Inventory | ConvertTo-Json | Out-File -FilePath $BaselineFile

    $Compare = Compare-Object -ReferenceObject @($Baseline.Keys) -DifferenceObject @($Inventory.Keys) -IncludeEqual
    $Compare | ForEach-Object {
        if ($_.SideIndicator -eq "==") {
            if ($Inventory[$_.InputObject] -ne $Baseline[$_.InputObject]) {
                $Exceptions.Add("CHANGED: " + $_.InputObject + ", " + $Inventory[$_.InputObject]) > $null
                $Global:Changed++
            }
        }
        elseif ($_.SideIndicator -eq "<=") {
            $Exceptions.Add("MISSING: " + $_.InputObject) > $null
            $Global:Missing++
        }
        elseif ($_.SideIndicator -eq "=>") {
            $Exceptions.Add("NEW: " + $_.InputObject + ", " + $Inventory[$_.InputObject]) > $null
            $Global:New++
        }
    }

    if ($Exceptions.Count -gt 0) {
        "`nThere are audit exceptions. Please see Violations File for more info."
        "UNABLE TO ACCESS TARGET: $NoAccess`nCHANGED: $Changed`nMISSING: $Missing`nNEW: $New"
        $Exceptions -join "`n" >> $Violations
    }
    else {
        "`nThere are no audit exceptions."
    }
}

ProcessTarget
ProcessFailedFiles
IntegrityCheck
ArchiveFiles
SendEvent
# GrafanaCall
CheckWebhookCall
"`nScript runtime: $((Get-Date -UFormat %s) - $Start)"