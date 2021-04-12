

# Veeam ONE RESTFul API and PowerShell

The purpose of this tutorial is to demonstrate how I went about connecting to the Veeam ONE REST API (version 11) using PowerShell, hopefully helping others that would also like to explore the new API. 

My inspiration came from Jorge de la Cruz and his Grafana Dashboard article here [[Experimental\] Grafana Dashboard for Veeam ONE v11 - Veeam R&D Forums](https://forums.veeam.com/post403687.html?hilit=Jorge#p403687) and wouldn't have been able to navigate the REST API without his insight.

## Making a Connection

PowerShell version 5.1 is used in this tutorial.

```powershell
PS C:\> $psversiontable.PSVersion

Major  Minor  Build  Revision
-----  -----  -----  --------
5      1      19041  868
```

The first thing you need to do is edit 2 variables, substituting your Veeam ONE server and domain user credentials.

```powershell
# ---------- DEFINE VARIABLES ---------- #
$veeamAPI = "https://veeamone.acme.com:1239"
$cred = Get-Credential -Message "Veeam One Credentials" -UserName "ACME\username"
```

My first attempt to connect using either Invoke-RestMethod or Invoke-WebRequest was a big fail with the following error.

```powershell
# Error Message
Invoke-RestMethod : The underlying connection was closed: Could not establish trust relationship for the SSL/TLS secure channel.
```

It turns out that PowerShell isn't going to let us connect using a self signed certificate. Although I found several recommended solutions, this is the one that worked for me connect to an endpoint using an untrusted certificate.

```powershell
# Ignore self signed certificate or request failS
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
```

When authenticating to the Rest API, you will receive a token good for 15 minutes. The token often expired while working on this script, so using a function seemed to simplify the authentication process. While credentials remain saved in the variable $cred, executing the function again provides another token for 15 minutes without having to enter a password again. It may just be my setup, but the authentication process can take up to 30 seconds, that's logging into the Veeam ONE web interface or waiting on a token. 

The Connect-VeeamAPI function requires 2 parameters, an endpoint URI and domain credentials for authenticating with Veeam ONE. If your Rest API connection isn't working, using -Verbose parameter with Invoke-RestMethod provides additional information for troubleshooting.

```powershell
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
```

Now were ready to make the connection. The function Connect-VeeamAPI appends the variable $appURI to the base URI, resulting in https://veeamone.acme.com:1239/api/token and is the endpoint we need for authentication as per [Veeam ONE REST API Reference](https://helpcenter.veeam.com/docs/one/rest/reference/one-rest.html) . Credentials are also passed using the $cred variable, the function will parse the username and password as required, returning our token saved in the $token variable.

```powershell
# ---------- REQUEST TOKEN ---------- #
$appURI = "/api/token"
$token = Connect-VeeamAPI -AppUri $appURI -Cred $cred
```

## Extracting Data

This first example will use our token to return information about Veeam ONE. Again we provide a new endpoint as defined in $appURI along with the token and our function appends it to create the full URI path. 

```powershell
# ---------- REQUEST ABOUT ---------- #
$appURI = "/api/v1/about"
Get-VeeamAPI -AppUri $appURI -Token $token
```

The token returned looks like this. Although I didn't try it, the token request also returns a "refresh_token" that can be used to refresh the token.

```powershell
PS C:\> $token

eyJhbGciOiJIUzI1NiIsImtpZCI6IldlYkFwaVNlY3VyaXR5S2V5IiwidHlwIjoiSldUIn0.eyJ1bmlxdWVfbmFtZSI6ImNvcnBcXG10ZWxsaWVyIiwicm9sZSI6IkFkbWluIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvc2lkIjoiUy0xLTUtMjEtNDg2MTk1OTc4LTM2MTEzNjg2NDAtMTgzMjY3NTE3Ni0xMTA0IiwiQWNjZXNzVG9rZW5JZCI6ImMyNzY4Njc2LTM1NjgtNDc0ZC1hZWE3LTkyYWM1Nzg4ZTJhYyIsIlVzZXJJZCI6IjEiLCJuYmYiOjE2MTgyNTM1MTYsImV4cCI6MTYxODI1NDQxNiwiaWF0IjoxNjE4MjUzNTE2fQ.ueheGpgIGPUYUh0wo21YIJLPN7SRBrf9qb4sANPsROA
```

Get-VeeamAPI function was created to simplify the process of returning data from a GET request. Simply provide the application (part of the URL that appears after the hostname and port) and token.

```powershell
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
```

Below is an example returning data using /api/v1/about.

```powershell
PS C:\> $appURI = "/api/v1/about"
PS C:\> Get-VeeamAPI -AppUri $appURI -Token $token | Format-List   

name    : Veeam ONE Reporting Service
version : 11.0.0.1379
machine : veeamone.acme.com
logPath : C:\ProgramData\Veeam\Veeam ONE Reporter\Logs
```

Try out these additional examples:

```powershell
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
```



## Widget Resource Example

The Veeam ONE Web Client has pre-defined dashboards, including Veeam Backup and Replication. This example will extract data from the Backup Infrastructure Inventory widget displayed below, then create an HTML view and embed in an email.

<img src="./pictures/widget.png" alt="Backup Infrastructure Inventory" style="zoom:100%;" />

The Widget Resource Example builds upon previous values of the $appURI variable, so the actual value is presented in a comment to provide further clarity as to the endpoint in reference. This example returns a list of all dashboards available in the Web Client.

```powershell
#################################################
# ---------- WIDGET RESOURCE EXAMPLE ---------- #
#################################################
$appURI = "/api/v1/dashboards"

# get all dashboards
$dashboards = Get-VeeamAPI -AppUri $appURI -Token $token
```

Jumping ahead, we arrive at our objective, list all of the objects available in the Backup Infrastructure Inventory widget.

```powershell
# get Backup Infrastructure Inventory
# $appURI = "/api/v1/dashboards/1/widgets/1/datasources/58/data?forceRefresh=false"
$appURI = $appURI + "/$infraWidgetID/data?forceRefresh=false"
$infraData = Get-VeeamAPI -AppUri $appURI -Token $token

PS C:\> $infraData.data | Format-Table

icon               name                   noAlarms warnings errors
----               ----                   -------- -------- ------
widget-bak-server  Backup Server (1)             0        0      1
widget-prox-server Proxy Server (17)            17        0      0
widget-rep-server  Repository Server (14)       14        0      0
widget-job         Backup Jobs (35)             35        0      0
widget-rcjob       Backup Copy Jobs (27)        25        0      2
widget-nas-job     NAS Backup Jobs (2)           2        0      0
```

Cleaning up our data to customize a report

```powershell
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

PS C:\> $report | Format-Table -Wrap -AutoSize

Object            Ok Warning Error
------            -- ------- -----
Backup Server      0       0     1
Proxy Server      17       0     0
Repository Server 14       0     0
Backup Jobs       35       0     0
Backup Copy Jobs   2      24     1
NAS Backup Jobs    2       0     0
```

### Convert to HTML

Before formatting the report with HTML, change the $outFile variable with a valid path and name if required.

```powershell
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
```

This is an example of the output file, although several of the headers have been modified in the script from that shown below.

![Backup Infrastructure Inventory](./pictures/sample.png)

### Send an Email

Finally, the HTML report is embedded in an email. I really like using the inline html, as there are no attachments to open.

```powershell
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
```

I hope this has been helpful.