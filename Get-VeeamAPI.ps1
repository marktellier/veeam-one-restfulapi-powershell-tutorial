<#
    4/12/2021
    Mark Telier

    Veeam ONE 11 RESTFul API Tutorial
    Demonstrate connecting to API and pulling data
#>

function Connect-VeeamAPI {
    [CmdletBinding()]
    param (
        [string] $AppUri,
        [pscredential] $Cred
    )

    begin {
        $header = @{
            "Content-Type" = "application/x-www-form-urlencoded"
            "accept" = "application/json"
        }
        
        $body = @{
            "grant_type" = "password"
            "username" = $cred.UserName 
            "password" = $cred.GetNetworkCredential().password
            "refresh_token" = " "
            "rememberMe" = " "
        }

        $requestURI = $veeamAPI + $appUri

        $tokenRequest = Invoke-RestMethod -Uri $requestURI -Headers $header -Body $body -Method Post -Verbose
        Write-Output $tokenRequest.access_token
    }
    
}

function Get-VeeamAPI {
    [CmdletBinding()]
    param (
        [string] $AppUri,
        [string] $Token
    )

    begin {
        $header = @{
            "accept" = "application/json"
            "Authorization" = "Bearer $Token"
        }

        $requestURI = $veeamAPI + $AppUri
        $results = Invoke-RestMethod -Method GET -Uri $requestUri -Headers $header
        
        Write-Output $results
    }
    
}


# ---------- DEFINE VARIABLES ---------- #
$veeamAPI = "https://veeamone.acme.com:1239"
$cred = Get-Credential -Message "Veeam One Credentials" -UserName "ACME\username"

# ignore self signed certificate or request failS
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

# ---------- REQUEST TOKEN ---------- #
$appURI = "/api/token"
$token = Connect-VeeamAPI -AppUri $appURI -Cred $cred

# ---------- REQUEST ABOUT ---------- #
$appURI = "/api/v1/about"
Get-VeeamAPI -AppUri $appURI -Token $token

# ---------- REQUEST INSTALLATION INFO ---------- #
$appURI = "/api/v1/about/installationInfo"
Get-VeeamAPI -AppUri $appURI -Token $token

# ---------- REQUEST LICENSE ---------- #
$appURI = "/api/v1/license"
Get-VeeamAPI -AppUri $appURI -Token $token

# ---------- REQUEST CURRENT USAGE ---------- #
$appURI = "/api/v1/license/currentUsage"
Get-VeeamAPI -AppUri $appURI -Token $token

# ---------- REQUEST DASHBOARDS ---------- #
$appURI = "/api/v1/dashboards"
Get-VeeamAPI -AppUri $appURI -Token $token


#################################################
# ---------- WIDGET RESOURCE EXAMPLE ---------- #
#################################################
$appURI = "/api/v1/dashboards"

# get all dashboards
$dashboards = Get-VeeamAPI -AppUri $appURI -Token $token

# select dashboard ids
$vbrDashID = ( $dashboards | Where-Object -Property "Name" -Like "Veeam Backup and Replication" ).dashboardId
$vsphereTrendDashID = ($dashboards | Where-Object -Property "Name" -Like "vSphere Trends").dashboardId
$vsphereAlarmDashID = ($dashboards | Where-Object -Property "Name" -Like "vSphere Alarms").dashboardId
$vsphereHostDashID = ($dashboards | Where-Object -Property "Name" -Like "vSphere Hosts and Clusters").dashboardId
$vsphereDatastoreDashID = ($dashboards | Where-Object -Property "Name" -Like "vSphere Datastores").dashboardId
$vsphereVMDashID = ($dashboards | Where-Object -Property "Name" -Like "vSphere VMs").dashboardId
$vsphereInfraDashID = ($dashboards | Where-Object -Property "Name" -Like "vSphere Infrastructure").dashboardId

# get VBR dashboard
# $appURI = "/api/v1/dashboards/1"
$appURI = $appURI + "/$vbrDashID"

$vbrDash = Get-VeeamAPI -AppUri $appURI -Token $token

# select widgets
$vbrWidgets = $vbrDash.dashboardWidgets

# select widget ids
$infraWidgetID = ($vbrWidgets | Where-Object -Property "Caption" -Like "Backup Infrastructure Inventory").widgetId
$vmsWidgetID = ($vbrWidgets | Where-Object -Property "Caption" -Like "Backup Infrastructure Inventory").widgetId
$windowWidgetID = ($vbrWidgets | Where-Object -Property "Caption" -Like "Backup Window").widgetId
$topJobWidgetID = ($vbrWidgets | Where-Object -Property "Caption" -Like "Top Jobs by Duration").widgetId
$jobStatsWidgetID = ($vbrWidgets | Where-Object -Property "Caption" -Like "Jobs Status").widgetId
$topRepoWidgetID = ($vbrWidgets | Where-Object -Property "Caption" -Like "Top Repositories by Used Space").widgetId

# get Backup Infrastructure Inventory Widget
# $appURI = "/api/v1/dashboards/1/widgets/1"
$appURI = $appURI + "/widgets/$infraWidgetID"
$infraWidget = Get-VeeamAPI -AppUri $appURI -Token $token

# get BackupAlarmsOverview ???
# $appURI = "/api/v1/dashboards/1/widgets/1/datasources"
$appURI = $appURI + "/datasources"
$infraWidget = Get-VeeamAPI -AppUri $appURI -Token $token

# select ID
$infraWidgetID = $infraWidget.datasourceId

# get Backup Infrastructure Inventory
# $appURI = "/api/v1/dashboards/1/widgets/1/datasources/58/data?forceRefresh=false"
$appURI = $appURI + "/$infraWidgetID/data?forceRefresh=false"
$infraData = Get-VeeamAPI -AppUri $appURI -Token $token

# We finally have our data
$infraData.data | Format-Table

# Tidy up the output
$infraData.data
$report = @()

foreach ($item in $infraData.data) {
    $props = [ordered]@{
        "Object"   = ($item.name -replace "\(.*\)").TrimEnd()
        "Ok"       = $item.noAlarms
        "Warning"  = $item.warnings
        "Error"    = $item.errors
    }

    $report += New-Object -TypeName psobject -Property $props
}
$report

# Wrap it in HTML
$outFile = "C:\Temp\VeeamONEReport.html"
$Header = @"
<style>
table {
    font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
    border-collapse: collapse;
    width: 100%;
}
th {
    padding-top: 12px;
    padding-bottom: 12px;
    text-align: left;
    background-color: #4CAF50;
    color: white;
}
</style>
<title>Report Title</title>
"@

$htmlReport = $report | ConvertTo-Html -Fragment
ConvertTo-Html -Body $htmlReport -Head $Header | Out-File $outFile
Invoke-Item $outFile

# Send to an inbox
$htmlBody = ConvertTo-Html -Body $htmlReport -Head $Header | Out-String
$message = @{
    To         = 'roadrunner@acme.com'
    From       = 'postmaster@acme.com'
    Subject    = 'Test Report'
    Body       = $htmlBody
    SmtpServer = 'emailserver.acme.com'
}

Send-MailMessage -BodyAsHtml @message
