# Nyan-Hunter - Dump AzureAD sign-in logs and analyze for initial threats
# Version: 1.0
# Tri Bui @ Ferris State University
# 06-18-2020
#


param(
    [Parameter()]
    [string]$file,
    [Parameter()]
    [int]$limit = 100000,
    [Parameter()]
    [int]$timeback = 100000,
    [Parameter()]
    [switch]$skip
    )


if ($PSBoundParameters['Debug']) {
    $DebugPreference = 'Continue'
    $isDebug = $true
}

$Global:floatMsg = "Nyan the Hunter!"
$database = (Get-Location).Path + '\NyanData\Nyan.db'

if(!$settings){
$settings = @{}

$settings.saveLogsToFile = $true

$settings.reportFolder = (Get-Location).Path + "\NyanReports\"
$tmp = (Test-Path $settings.reportFolder)
If(!$tmp)
{
      New-Item -ItemType Directory -Force -Path $settings.reportFolder
}

$settings.logFolder = (Get-Location).Path + "\AzureLogs\"
$tmp = (Test-Path $settings.logFolder)
if(!$tmp)
{
      New-Item -ItemType Directory -Force -Path $settings.logFolder
}

$settings.outfile = $settings.logFolder + "\AzureAD-logs-" + (Get-Date).ToString("yyyy-MM-dd_HH-mm") + ".txt"

$settings.ReportFile = $settings.reportFolder + "\Nyan-Hunter-Results_" + (Get-Date).tostring("MM-dd-yyyy_HH-mm") + ".html"
#$settings.threatIPsFile = $settings.reportFolder + "\Nyan-ThreatsIPs.csv"
#$settings.AzureRiskFile = $settings.reportFolder + "\Nyan-AzureRiskUsers.csv"

# Settings ######################################
$settings.credsFile = ".\NyanData\creds.xml"
$settings.timefile = ".\NyanData\lastrun.txt"



$settings.limit = 100000
$settings.timeback = 12
$settings.jobLimit = 20

#########################################################################################################
# Sending mail settings
# Set $sendMail to enable/disable sending report

$sendMail = $false
$silentMail = $true

$mailfrom = "[CHANGE_ME]" 
$mailto = @("[CHANGE_ME]")
#$mailcc = @("[CHANGE_ME]") 
$mailcc = @("") 
$mailSub = "Nyan Hunter Results " + (Get-Date).tostring("MM-dd-yyyy HH-mm")
$mailBody = "Nyan Hunter Results for " + (Get-Date).tostring("MM-dd-yyyy HH-mm")
$mailfiles = @($settings.ReportFile,$settings.threatIPsFile,$settings.AzureRiskFile)
$mailserver = "ferris-edu.mail.protection.outlook.com"

$mailconf = @{
    From = $mailfrom 
    To = $mailto 
    Subject = $mailSub 
    Body = $mailBody 
    SmtpServer = $mailserver
    Attachments = $mailfiles
}
if($mailcc) { $mailconf.Add("Cc",$mailcc) }

#########################################################################################################



if(!$timeback) {
    $timeback = $settings.timeback
}

# Logs limit
if(!$limit) {
    $limit = $settings.limit
}

# Failed logs filter
$settings.lockdown = 3
$settings.userlimit = 3

# Azure risk level filtering
$settings.riskFilter = @("medium","high")

# Whitelist Localtion
$settings.whiteCountries = @("US")
$settings.whiteState = @("Michigan")
$settings.WhiteIP = "^161\.57\.([1-9]?\d|[12]\d\d)\.([1-9]?\d|[12]\d\d)$|^204\.38\.(2[4-9]|3[01])\.([1-9]?\d|[12]\d\d)$"

$settings.badErrorCode = @("50053","50126")

# MS Graph API settings
$settings.tenantid = '[CHANGE_ME]'
$settings.clientid = "[CHANGE_ME]"
$settings.clientsecret = "[CHANGE_ME]"
$settings.tenantDomain = '[CHANGE_ME]'


# API token for IP service (ipinfo.io) # Free account has 50,000 queries/month
$settings.IPTOKEN = "[CHANGE_ME]"

# Using an array of free API keys for rotation ;)
# APi token for ip2proxy.com
$settings.VPNTOKEN1 = @("[CHANGE_ME]")
# API token for proxy detection (proxycheck.io) # Free account has 1000 queries/day
$settings.VPNTOKEN = @("[CHANGE_ME]")


# IP Proxy table
$settings.ProxyTableFile = ".\NyanData\ProxyTable.xml"
if (Test-Path $settings.ProxyTableFile -PathType Leaf) {
    $settings.ProxyTable = Import-Clixml $settings.ProxyTableFile
} else { $settings.ProxyTable = @{} }

# IP to country table
$settings.IPTableFile = ".\NyanData\IPLocation.xml"
if (Test-Path $settings.IPTableFile -PathType Leaf) {
    $settings.IPTable = Import-Clixml $settings.IPTableFile
} else { $settings.IPTable = @{} }


}

if (Test-Path $settings.timefile -PathType Leaf) {
    $lastrun = Get-Content $settings.timefile
}
if(!$lastrun -or $skip){
    $lastrun = (Get-Date).AddHours(-$timeback).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
}

$global:totalLogs = 0



function sendReport {

    if($sendMail) {

        $zfilename = $settings.reportFolder + "\Nyan-Hunter-Results_" + (Get-Date).tostring("MM-dd-yyyy_HH-mm") + ".zip"
        $compress = @{
          #Path = @($settings.ReportFile,$settings.threatIPsFile,$settings.AzureRiskFile)
          Path = @($settings.ReportFile)
          CompressionLevel = "Fastest"
          DestinationPath = $zfilename
        }
        Compress-Archive @compress

        #Compress-Archive -Path $settings.ReportFile -DestinationPath $zfilename
        #$settings.ReportFile = $zfilename
        $mailconf.Remove("Attachments")
        $mailconf.Add("Attachments",$zfilename)

        if($silentMail) { Send-MailMessage @mailconf; Write-Debug "Mail sent" }
        else {
            $sending = Read-Host "Send report to preset emails? (y/N): "
            if(@("y","Y","").Contains($sending)) {
                try {
                    Send-MailMessage @mailconf
                } catch { Write-Host "Mail sending failed" -ForegroundColor Red }
                Write-Host "Mail sent"
            }
        }
    }

}

function execQ {
param(
    [Parameter()]
    [string]$query,
    [Parameter()]
    [string]$dbs = $database
    )
    #Write-Host $query
    return Invoke-SqliteQuery -Query $query -DataSource $dbs

}


function JobHold {

    $running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
    if ($running.Count -ge $settings.jobLimit) {
        Write-Progress -Activity $global:floatMsg -CurrentOperation ("Jobs reached limit, waiting for free slot..")
        $running | Wait-Job -Any | Out-Null
        Start-Sleep -m 500
    }

}


function getProxyType {
param(
    [Parameter(Mandatory)]
    [string]$ip
    )

    $ip = $ip.Trim()
    Write-Debug $ip
    $found = execQ "SELECT * FROM IPProxy WHERE IP = '$($ip)'"
    if(!$found) {
        $url = "http://proxycheck.io/v2/$($ip)?key=$($settings.VPNTOKEN)&days=60&vpn=1&asn=1&node=1&time=1&inf=1&risk=2&port=1&seen=1&tag=msg"
        $api = (curl $url) -replace "'", ""
        $proxy = ConvertFrom-Json -InputObject $api
        #Write-Host $url $proxy."$($ip)"
        $data = $proxy."$($ip)"
        execQ "INSERT INTO IPProxy(IP,asn,provider,continent,country,isocode,region,regioncode,city,latitude,longitude,proxy,type,risk,port,AttackHistory)`
                 VALUES('$($ip)','$($data.asn)','$($data.provider)','$($data.continent)','$($data.country)','$($data.isocode)','$($data.region)',`
                        '$($data.regioncode)','$($data.city)','$($data.latitude)','$($data.longitude)','$($data.proxy)','$($data.type)','$($data.risk)','$($data.port)','$($data."attack history")')"
        $proxy = $proxy."$($ip)"
        Write-Debug "IP API #1 called (proxycheck.io)"
    } else {
        $proxy = $found
    }

    return $proxy
}


$getPType = {

function execQ {
param(
    [Parameter()]
    [string]$query,
    [Parameter()]
    [string]$dbs = $args[1]
    )
    #Write-Host $query
    #Write-Host $dbs
    return Invoke-SqliteQuery -Query $query -DataSource $dbs

}

function getProxyType {
param(
    [Parameter(Mandatory)]
    [string]$ip
    )

    $ip = $ip.Trim()
    Write-Debug $ip
    $found = execQ "SELECT * FROM IPProxy WHERE IP = '$($ip)'"
    if(!$found) {
        $url = "http://proxycheck.io/v2/$($ip)?key=$($settings.VPNTOKEN)&days=60&vpn=1&asn=1&node=1&time=1&inf=1&risk=2&port=1&seen=1&tag=msg"
        $api = (curl $url) -replace "'", ""
        $proxy = ConvertFrom-Json -InputObject $api
        #Write-Host $url $proxy."$($ip)"
        $data = $proxy."$($ip)"
        execQ "INSERT INTO IPProxy(IP,asn,provider,continent,country,isocode,region,regioncode,city,latitude,longitude,proxy,type,risk,port,AttackHistory)`
                 VALUES('$($ip)','$($data.asn)','$($data.provider)','$($data.continent)','$($data.country)','$($data.isocode)','$($data.region)',`
                        '$($data.regioncode)','$($data.city)','$($data.latitude)','$($data.longitude)','$($data.proxy)','$($data.type)','$($data.risk)','$($data.port)','$($data."attack history")')"
        $proxy = $proxy."$($ip)"
        Write-Debug "IP API #1 called (proxycheck.io)"
    } else {
        $proxy = $found
    }

    return $proxy
}

}

# Analyze if IPs are VPNs/Proxies, known threats, etc from proxycheck.io
function getProxyRisk {
param(
    [Parameter(Mandatory)]
    [string]$ip
    )

    $ips = ""
    $RiskCount = 0
    $ip.Split(",") | % {
        $found = execQ "SELECT * FROM IPProxy WHERE IP = '$($_)'"
        if(!$found) { $ips += "$($_)," } 
        $found = $null
    }
    $ips = $ips.TrimEnd(",")

    if($ips.Split(",")[0] -ne "") {
        $api = (curl -Method Post "http://proxycheck.io/v2/?key=$($settings.VPNTOKEN)&days=60&vpn=1&asn=1&node=1&time=1&inf=1&risk=2&port=1&seen=1&tag=msg" -Body "ips=$($ips)") -replace "'", ""
        $proxy = ConvertFrom-Json -InputObject $api
        #Write-Host $proxy -ForegroundColor Yellow
        $ips.Split(",") | % {
            $data = $proxy."$($_)"
            execQ "INSERT INTO IPProxy(IP,asn,provider,continent,country,isocode,region,regioncode,city,latitude,longitude,proxy,type,risk,port,AttackHistory)`
                    VALUES('$($_)','$($data.asn)','$($data.provider)','$($data.continent)','$($data.country)','$($data.isocode)','$($data.region)',`
                           '$($data.regioncode)','$($data.city)','$($data.latitude)','$($data.longitude)','$($data.proxy)','$($data.type)','$($data.risk)','$($data.port)','$($data."attack history")')"
        }
        Write-Debug "Multi-IP API called (proxycheck.io)"
    }

    $ip.Split(",") | % { 
        $found = execQ "SELECT * FROM IPProxy WHERE IP = '$($_)'"
        if($found) {
            # If proxy but not VPN = risk
            if(($found.isProxy -eq "YES" -and $found.Proxytype -ne "VPN") -or 
                ($found.Proxy -eq "yes" -and $found.type -ne "VPN")) {
                    $RiskCount++
            # VPN + known attack history = risk
            # Change to comment to switch between riskscore and attack history base
            } elseif ($found.AttackHistory -or $found.risk -gt 66) { $RiskCount++  }
        }
        $found = $null   
    
    }

    return $RiskCount

}



function getToken {
param(
    [Parameter()]
    [string]$tenantid = $settings.tenantid,
    [Parameter()]
    [string]$tenantDomain = $settings.tenantDomain,
    [Parameter()]
    [string]$clientid = $settings.clientid,
    [Parameter()]
    [string]$clientsecret = $settings.clientsecret
    )

    $body = @{
        "client_id" = $clientid 
        "client_secret" = $clientsecret
        "scope" = "https://graph.microsoft.com/.default"
        "grant_type" = "client_credentials"
        "Content-Type" = "application/x-www-form-urlencoded"

    }

    $request = curl -Method POST "https://login.microsoftonline.com/$($tenantid)/oauth2/v2.0/token" -Body $body

    $token = ($request.Content | ConvertFrom-Json).access_token

    return $token

}


function logsDump {
param(
    [Parameter()]
    [string]$file = $null,
    [Parameter()]
    [int]$limit = 100000,
    [Parameter()]
    [string]$from,
    [Parameter()]
    [string]$credsFile = ".\NyanData\creds.xml",
    [Parameter()]
    [string]$codeFilter = $null
    )

    Write-Progress -Activity $global:floatMsg -CurrentOperation ("Dumping Azure AD logs.. ")
    #$accessToken = (([Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens['AccessToken']).AccessToken).TrimEnd()
    $accessToken = getToken
    #Write-Host $accessToken
    
    $headers = @{ "Authorization" = "Bearer $($accessToken)";
                  "Host" = "graph.microsoft.com";
                  "Accept" = "application/json";
                  "Accept-Encoding" = "gzip, deflate"
                  "Scope" = "https://graph.microsoft.com/.default"
                }
    #$headers | FL
    #Break

    if(!$codeFilter) {
        for($i = 0; $i -lt $settings.badErrorCode.Count; $i++) { 
            if($i -eq 0) { $codeFilter += "status/errorCode eq $($settings.badErrorCode[$i])" }
            else { $codeFilter += " or status/errorCode eq $($settings.badErrorCode[$i])" }
        }
    }


        #$request = curl "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=($($codeFilter)) and createdDateTime gt $($from)&`$top=$($limit)" -Headers $headers
        $request = curl "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=($($codeFilter)) and createdDateTime gt $($from)" -Headers $headers
        #$request = curl "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime gt $($from)&`$top=$($limit)" -Headers $headers             # All logs
        #$request = curl "$($url)&`$filter=createdDateTime gt $($from) and status/errorcode eq 0&`$top=$($limit)" -Headers $headers                              # Success only

        $i = 0;
        $max = ($limit/1000)
    
        $jobArray = @()

        do {
            $content = $request.Content | ConvertFrom-Json
            $Logs += $content.Value
            if($content."@odata.nextLink") {
                try {
                    Start-Sleep 1
                    $request = curl $content."@odata.nextLink" -Headers $headers
                
                } catch { 
                    $ErrorMessage = $_.Exception.Message
                    $FailedItem = $_.Exception.ItemName
                    Write-Host $ErrorMessage -ForegroundColor Yellow
                    Send-MailMessage -From "Security@ferris.edu" -To "tribui@ferris.edu" -Subject "Nyan Hunter logs dumping throttled!" -Body "Nyan Hunter dumping throttled at $(Get-Date)`n`n$($content."@odata.nextLink")" -SmtpServer "ferris-edu.mail.protection.outlook.com" -Port "25" -BodyAsHtml -Priority High
                    #Break
                }
            } else { Break }
            Write-Debug $content."@odata.nextLink"
            $i++
        } while ($i -lt $max)

        if($Logs -and $settings.saveLogsToFile -and $file) {
            Write-Progress -Activity $global:floatMsg -CurrentOperation ("Saving logs to file $($file)..")
            $Logs | ConvertTo-Json | Out-File $file
            Write-Progress -Activity $global:floatMsg -CurrentOperation ("Saving logs to file $($file).. DONE")
        }

        $now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
        $now | Out-File $settings.timefile

        Write-Progress -Activity $global:floatMsg -CurrentOperation ("Dumping Azure AD logs.. DONE")


    return $Logs
}

# Credit to https://www.pwsh.ch/powershell-how-to-split-an-array-into-smaller-arrays-chunks-173.html
function Split-Every($inArray, $chunkSize=5) {
    #$chunkSize = 3
    $outArray = @()
    $parts = [math]::Ceiling($inArray.Length / $chunkSize)
 
    # Splitting the array to chunks of the same size
    for($i=0; $i -le $parts; $i++){
        $start = $i*$chunkSize
        $end = (($i+1)*$chunkSize)-1
        $outArray += ,@($inArray[$start..$end])
    }

    return $outArray
}


function ThreatsHunt {
param(
    [Parameter(Mandatory)]
    [PSObject]$logs
    )

    $global:totalLogs = ($logs | Measure-Object).Count
    Write-Debug $totalLogs

    $from = ($logs | Select -Last 1 createdDateTime).createdDateTime

    $theats = @()
    Write-Progress -Activity $global:floatMsg -CurrentOperation ("Identifying suspicious IPs.. ")
    # Filter failed logs out of the big chunk, group them by IP
    $failedlogs = ($logs | Where {($_.status.errorcode -in $settings.badErrorCode)} | Group-Object IpAddress | Sort Count -Descending | Where Count -gt $settings.lockdown)

    # Extracting risky IP
    $RiskLogsByIp = $failedlogs | Where { ((($_.Group | Select userPrincipalName -Unique) | Measure-Object).Count -gt $settings.userlimit -and 
                            #(($_.Group | Group-Object userPrincipalName | Select Name, Count) | Measure-Object Count -Average) -and
                            ($_.Group | Select -First 1 {$_.Location.State}) -notin $settings.whiteState -and
                            $_.Name -notmatch $settings.whiteIP ) } 
    Write-Progress -Activity $global:floatMsg -CurrentOperation ("Identifying suspicious IPs.. DONE")
    #Write-Debug ($RiskLogsByIp | Out-String)

    if($RiskLogsByIp) {
        
        $chunks = Split-Every $RiskLogsByIp 20
        $hitLogs = @()
        #Write-Host ($chunks | Measure-Object).Count ($chunks | FT | Out-String)

        for($i = 0; $i -lt ($chunks | Measure-Object).Count; $i++) {
            $IpFilter = "(status/errorCode eq 0) and ("
            for($j = 0; $j -lt ($chunks[$i] | Measure-Object).Count; $j++) { 
                if($j -eq 0) { $IpFilter += "(IpAddress eq '$($chunks[$i].Name[$j])')" }
                else { $IpFilter += " or (IpAddress eq '$($chunks[$i].Name[$j])')" }
            }
            $IpFilter += ")"
            if(($chunks[$i] | Measure-Object).Count -gt 0) {
                $hitLogs += logsDump -codeFilter $IpFilter -from $from
            }
            #Write-Host $IpFilter $hitLogs.Count $from         
            $IpFilter = ""
        }

        $IPList = $RiskLogsByIp.Name -join ","
        $ProxyCount = getProxyRisk $IPList
        Write-Debug ($IPList + "`n" + $ProxyCount)

        $jobArray = @()

        # Analyzing
        $RiskLogsByIp | Where { $_ -ne $null } | % {
        JobHold
        Write-Progress -Activity $global:floatMsg -CurrentOperation ("Analyzing $($_.Name).. ")
        $accessToken = getToken
        $record = $null

        ## Multi-threads ##

        $jobArray += Start-Job -Name $_.Name -ScriptBlock {
            Write-Debug $args[0].Name
            # $args[0].Name = an IP address
            # $args[0].Group = all failed logs belong to the IP above

            $ip = $args[0].Name
            #$failedCount = ($logs | Where {$args[0].status.errorcode -in $settings.badErrorCode -and $args[0].IpAddress -eq $ip} | Measure-Object).Count
            $failedCount = ($args[0].Group | Measure-Object).Count
            # Group the failed logs to username
            $GroupByUser = ($args[0].Group | Group-Object userPrincipalName)
            $avgStrike = (( ($GroupByUser | Select Name, Count) | Measure-Object -Property Count -Average).Average)
            $timespan = @()
            if($avgStrike -gt 1) {
                $GroupByUser | % { 
                                    ##Write-Host ($args[0].Name) -ForegroundColor Red
                                    ##Write-Host ($args[0].Group | Out-String) -ForegroundColor Yellow
                                    for($i = 0; $i -lt ($args[0].Group | Measure-Object).Count-1; $i++) {
                                        $tmp = (New-TimeSpan -Start $args[0].Group[$i+1].createdDateTime -End $args[0].Group[$i].createdDateTime)
                                        $timespan += $tmp.TotalSeconds
                                        #Write-Host $args[0].Group[$i].createdDateTime -ForegroundColor Yellow
                                        ##Write-Host $tmp -ForegroundColor Yellow
                                    }
                                    #Write-Host "###############" -ForegroundColor Green
                              }
            }

            for($i = 0; $i -lt ($args[0].Group | Measure-Object).Count-1; $i++) {
                $tmp = (New-TimeSpan -Start $args[0].Group[$i+1].createdDateTime -End $args[0].Group[$i].createdDateTime)
                $timespan += $tmp.TotalSeconds
                #Write-Host $args[0].Group[$i].createdDateTime
                ##Write-Host $tmp -ForegroundColor Yellow
            }

            $avgStrikeTime = [Math]::round(($timespan | Measure-Object -Average).Average,2)


            $logs = $args[2]

            $failedUsers = @($GroupByUser | Select Name, Count)
            $hitCount = ($logs | Where {$_.status.errorcode -eq 0 -and $_.IpAddress -eq $ip} | Measure-Object).Count
            $atRisk = (($logs | Where {$_.status.errorcode -eq 0 -and $_.IpAddress -eq $ip} | Select userPrincipalName -Unique).userPrincipalName)

            $ipDetail = getProxyType $ip

            $record = New-Object -TypeName psobject
            $record  | Add-Member -MemberType NoteProperty -Name IP -Value $ip
            $record  | Add-Member -MemberType NoteProperty -Name IPDetail -Value $ipDetail
            $record  | Add-Member -MemberType NoteProperty -Name FailedCount -Value $failedCount
            $record  | Add-Member -MemberType NoteProperty -Name UnderAttackUsers -Value $failedUsers
            $record  | Add-Member -MemberType NoteProperty -Name UnderAttackCount -Value ($failedUsers | Measure-Object).Count
            $record  | Add-Member -MemberType NoteProperty -Name AvgStrike -Value $avgStrike
            $record  | Add-Member -MemberType NoteProperty -Name AvgStrikeTime -Value $avgStrikeTime
            $record  | Add-Member -MemberType NoteProperty -Name HitCount -Value $hitCount
            $record  | Add-Member -MemberType NoteProperty -Name AtRiskUsers -Value $atRisk
            #$record  | Add-Member -MemberType NoteProperty -Name FailedLogs -Value ($args[0].Group | ConvertTo-Json)
            $record  | Add-Member -MemberType NoteProperty -Name FailedLogs -Value ($args[0].Group)
            $record  | Add-Member -MemberType NoteProperty -Name HitLogs -Value (($logs | Where {$_.status.errorcode -eq 0 -and $_.IpAddress -eq $ip}))
            #Write-Host $record -ForegroundColor Yellow
            return $record
        } -ArgumentList ($_,$database,$hitLogs) -InitializationScript $getPType
            #$threats += @($record)

            #Write-Host ($record | FL | Out-String)

            #Write-Host $_.Name -ForegroundColor Yellow
            #Write-Host ($_.Group | Select userPrincipalName -Unique)
        }

        Write-Debug ($jobArray | Out-String)
        #$wait = Wait-Job $jobArray
        Write-Progress -Activity $global:floatMsg -CurrentOperation ("Waiting for results.. ")

        $threats = ($jobArray | Wait-Job | Receive-Job)
        Write-Progress -Activity $global:floatMsg -CurrentOperation ("Waiting for results.. DONE")

        <#
        $threats | Select IP, IPDetail, FailedCount, UnderAttackCount,
                    @{Name="UnderAttackUsers"; Expression={$_.UnderAttackUsers.Name -join "," }}, HitCount,
                    @{Name="AtRiskUsers"; Expression={$_.AtRiskUsers -join ","}}, AvgStrike,
                    @{Name='AddedDate'; Expression={(Get-Date).tostring("MM-dd-yyyy HH:mm")} }  |
                Export-Csv -Path $settings.threatIPsFile -NoTypeInformation -Append
        #>

        $data = $threats | Select IP, IPDetail, FailedCount, UnderAttackCount,
                    @{Name="UnderAttackUsers"; Expression={$_.UnderAttackUsers.Name -join "," }}, HitCount,
                    @{Name="AtRiskUsers"; Expression={$_.AtRiskUsers -join ","}}, AvgStrike,
                    @{Name='AddedDate'; Expression={(Get-Date).tostring("MM-dd-yyyy HH:mm")} }  | Out-DataTable
        if($data) {
            $exec = Invoke-SQLiteBulkCopy -DataTable ($data) -DataSource $database -Table ThreatIPs -Confirm:$false
        }
    }


    #Write-Debug ($threats | FL | Out-String)
    #Write-Debug ($threats.Count | FL | Out-String)
    return $threats

}


function getAzureRisk {
param(
    [Parameter()]
    [string]$from
    )

    $riskUsers = @()
    Write-Progress -Activity $global:floatMsg -CurrentOperation ("Getting Azure AD Risky Users.. ")

    $accessToken = getToken
    
    $headers = @{ "Authorization" = "Bearer $($accessToken)";
                  "Host" = "graph.microsoft.com";
                  "Accept" = "application/json";
                  "Accept-Encoding" = "gzip, deflate"
                  "Scope" = "https://graph.microsoft.com/.default"
                }

    for($i = 0; $i -lt $settings.badErrorCode.Count; $i++) { 
        if($i -eq 0) { $codeFilter += "status/errorCode eq $($settings.badErrorCode[$i])" }
        else { $codeFilter += " or status/errorCode eq $($settings.badErrorCode[$i])" }
    }

    $request = curl "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=(riskState eq 'atRisk') and (status/errorCode eq 0) and (createdDateTime gt $($from))" -Headers $headers
    $content = $request.Content | ConvertFrom-Json
    $logs = $content.Value

    $riskUsers = $logs | Where { $_.status.errorcode -eq 0 -and $_.riskState -ne "none" -and
                               ($_.riskLevelAggregated -in $settings.riskFilter -or $_.riskLevelDuringSignIn -in $settings.riskFilter) 
                             } | Group-Object userPrincipalName

    Write-Debug ($riskUsers | FL | Out-String)

    $azRisk = $riskUsers.Group | Select -Unique userPrincipalName, IpAddress, ClientAppUsed, riskLevelAggregated, riskLevelDuringSignIn, @{Name='AddedDate'; Expression={(Get-Date).tostring("MM-dd-yyyy HH:mm")} }
    #$azRisk | Export-Csv -Path $settings.AzureRiskFile -NoTypeInformation -Append
    $data = $azRisk  | Out-DataTable
    if($azRisk) {
        $exec = Invoke-SQLiteBulkCopy -DataTable ($data) -DataSource $database -Table AzureRiskyUsers -Confirm:$false
    }

    Write-Progress -Activity $global:floatMsg -CurrentOperation ("Getting Azure AD Risky Users.. DONE")
    return $riskUsers

}



function ConvertTo-HTMLTable ($obj) {
# Credit to: https://stackoverflow.com/users/9898643/theo
# Accepts a System.Data.DataTable object or an array of PSObjects and converts to styled HTML table
# add type needed to replace HTML special characters into entities
    Add-Type -AssemblyName System.Web

    $sb = New-Object -TypeName System.Text.StringBuilder
    [void]$sb.AppendLine('<table>')
    if ($null -ne $obj) {
        if (([object]$obj).GetType().FullName -eq 'System.Data.DataTable'){
            # it is a DataTable; convert to array of PSObjects
            $obj = $obj | Select-Object * -ExcludeProperty ItemArray, Table, RowError, RowState, HasErrors
        }
        $headers = $obj[0].PSObject.Properties | Select -ExpandProperty Name
        [void]$sb.AppendLine('<thead><tr>')
        foreach ($column in $headers) {
            [void]$sb.AppendLine(('<th>{0}</th>' -f [System.Web.HttpUtility]::HtmlEncode($column)))
        }
        [void]$sb.AppendLine('</tr></thead><tbody>')
        $row = 0
        $obj | ForEach-Object {
            # add inline style for zebra color rows
            if ($row++ -band 1) {
                $tr = '<tr style="background-color: {0};">' -f $oddRowBackColor
            } 
            else {
                $tr = '<tr>'
            }
            [void]$sb.AppendLine($tr)
            foreach ($column in $headers) {
                [string]$val = $($_.$column)
                if ([string]::IsNullOrWhiteSpace($val)) { 
                    $td = '<td>&nbsp;</td>' 
                } 
                else { 
                    $td = '<td>{0}</td>' -f [System.Web.HttpUtility]::HtmlEncode($val)
                }
                [void]$sb.Append($td)
            }
            [void]$sb.AppendLine('</tr>')
        }

        [void]$sb.AppendLine('</tbody>')
    }
    [void]$sb.AppendLine('</table>')

    return $sb.ToString()
}



function exportReport {
param(
    [Parameter()]
    [PSObject]$threats = $null,
    [Parameter()]
    [PSObject]$AzureRiskUsers = $null
    )

    #$settings.ProxyTable | Export-Clixml -Path $settings.ProxyTableFile
    Write-Progress -Activity $global:floatMsg -CurrentOperation ("Generating report header.. ")

    $jobArray = $jobArray2 = @()
    $underAttack = ($threats.UnderAttackUsers.Name | Where {$_ -ne $null} | Select -Unique)
    $atRisk = ($threats.AtRiskUsers | Where {$_ -ne $null} | Select -Unique)


    $html = "
        <head>
        <title>Risk Logs Report</title>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <link rel='stylesheet' href='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css'>
        <script src='https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js'></script>
        <script src='https://maxcdn.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js'></script>
        </head>
        <style>
        #TABLE { margin-bottom: 5px; border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
        TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #3179de;}
        TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
        .table-condensed {
              font-size: 12px;
        }
        .collapse.show {
          visibility: visible;
        }
        a, a:hover,a:visited, a:focus {
            text-decoration:none;
        }
        table.dataTable thead .sorting:after,
        table.dataTable thead .sorting:before,
        table.dataTable thead .sorting_asc:after,
        table.dataTable thead .sorting_asc:before,
        table.dataTable thead .sorting_asc_disabled:after,
        table.dataTable thead .sorting_asc_disabled:before,
        table.dataTable thead .sorting_desc:after,
        table.dataTable thead .sorting_desc:before,
        table.dataTable thead .sorting_desc_disabled:after,
        table.dataTable thead .sorting_desc_disabled:before {
        bottom: .5em;
        }
        </style>
        <body>
        <div class='container-fluid'>
            <div class='h1 text-primary card-header font-weight-bold px-1'>
              Nyan-Hunter Report
            </div>
            <div class='h5 font-italic font-weight-light px-1 mb-4'>Date: $((Get-Date).ToString('MM-dd-yyyy hh:mm:ss tt'))</div>
        </div>
        <div class='container-fluid mb-5'>
          <div class='row border border-light py-1'>
            <div class='col-2'>Total logs analyzed</div>
            <div class='col'><span class='badge badge-primary'>$($totalLogs)</span> (from <b>$($lastrun)</b> - limit <b>$($limit)</b>)</div>
            <div class='w-100'></div>
            <div class='col-2'>Threats IP(s)</div>
            <div class='col'><span class='badge badge-danger'>
                $(($threats | Measure-Object).Count)</span> 
                $($threats | Where {$_ -ne $null} | % { 
                        $str += "<a class='text-danger' href='#IP$(($_.IP).Replace(".","-"))_head'>" + $_.IP + "</a>, " }; 
                        if($str) {
                            $str = $str.TrimEnd(", ");
                            $str
                        } )
                $($str = '')
            </div>
            <div class='w-100'></div>
            <div class='col-2'>At Risk User(s)</div>
            <div class='col'><span class='badge badge-danger'>
            $(($atRisk | Measure-Object).Count)</span>
            $($atRisk | % {
                    $str += "<span class='text-danger'>$($_)</span>, "
                    }
                    if($str) {
                            $str = $str.TrimEnd(", ");
                            $str
                    }
             $str = '' )
            </div>
            <div class='w-100'></div>
            <div class='col-2'>Under Attack User(s)</div>
            <div class='col'><span class='badge badge-warning'>
            $(($underAttack | Measure-Object).Count)</span>
            $($underAttack | % {
                    $str += "<span class='text-warning'>$($_)</span>, "
                    }
                    if($str) {
                            $str = $str.TrimEnd(", ");
                            $str
                    }
             $str = '')
            </div>

            <div class='w-100'></div>
            <div class='col-2'>AzureAD Reported Risky User(s)</div>
            <div class='col'><span class='badge badge-warning'>
                $(($AzureRiskUsers | Measure-Object).Count)</span>
                $($AzureRiskUsers |  % { 
                        $str += "<a class='text-warning'  href='#Azure_head'>" + $_.Name + "</a>, " }; 
                        if($str) {
                            $str = $str.TrimEnd(", ");
                            $str
                        } )
                $($str = '')
            </div>
          </div>
        </div>
        "

              

    ($threats | Sort HitCount, FailedCount, UnderAttackCount -Descending ) | % {
    Write-Progress -Activity $global:floatMsg -CurrentOperation ("Generating report for $($_.IP).. ")
        $html += "<div class='container-fluid mb-5'>"    
        $html += "<link rel='stylesheet' href='https://cdn.datatables.net/1.10.21/css/jquery.dataTables.min.css'>
                  <script src='https://cdn.datatables.net/1.10.21/js/jquery.dataTables.min.js'></script>"

        if(($_.HitLogs | Measure-Object).Count -gt 0) {
            $riskhead = "<div id='IP$(($_.IP).Replace(".","-"))_head' class='button btn-danger py-1 px-1 font-weight-bold border border-secondary'>$($_.IP)</div>"
        } else {
            $riskhead = "<div id='IP$(($_.IP).Replace(".","-"))_head' class='button btn-warning text-danger py-1 px-1 font-weight-bold border border-secondary'>$($_.IP)</div>"
        }

        $html += $riskhead
        $html += $_ | Select @{Name='#IP';Expression={$_.IP};}, 
                             @{Name='#IP Detail';Expression={ "<div class='container-fluid'>"
                                                                        $_.IPDetail | % {
                                                                        "<div class='table-md w-100 ml-0'>"
                                                                            $_.PSObject.Properties | %  {
                                                                                 "<div class='row px-0 mx-0'>
                                                                                 <div class='col-2 px-0 text-left d-inline border-bottom'>" + $_.Name + ":</div>
                                                                                 <div class='col-6 font-weight-bold d-inline border-bottom'>" + $_.Value + "</div>
                                                                                 </div>"
                                                                            }
                                                                        "</div>"
                                                                        }
                                                                        "</div>"
                                                                      };},
                             @{Name='#Failed Count';Expression={($_.FailedLogs | Measure-Object).Count};}, 
                             @{Name='#Under Attack Users';Expression={ "<span class='font-weight-bold'>"
                                                                      ($_.UnderAttackUsers | Where {$_ -ne $null}).Name -join ", "
                                                                     "</span>" 
                                                                     };}, 
                             @{Name='#Avg. Strike per User';Expression={$_.AvgStrike};}, 
                             @{Name='#Avg. Strike Interval';Expression={
                                                                   $ts = New-TimeSpan -Seconds $_.AvgStrikeTime
                                                                   "{0:00}h:{1:00}m:{2:00}s" -f $ts.Hours,$ts.Minutes,$ts.Seconds
                                                                 };}, 
                             @{Name='#Hit Count';Expression={ $_.HitCount } }, 
                             @{Name='#At Risk Users';Expression={ "<span class='font-weight-bold'>"
                                                                 ($_.AtRiskUsers | Where {$_ -ne $null}) -join ", "
                                                                   "</span>"  
                                                                     };} |
                             ConvertTo-Html -Fragment -As List
        $html = $html -replace "<td>#","<td style='width:15%'>"
        $html += "<div class='container-fluid float-right px-0'>"

        if(($_.FailedLogs | Measure-Object).Count -gt 0) {

            $html += "
                        <button class='btn btn-primary btn-sm mb-1 font-weight-bold float-right ml-1' type='button' data-toggle='collapse' 
                        data-target='#IP$((($_.IP).Replace(".","-")).Replace(":","-"))' aria-expanded='false' aria-controls='IP$((($_.IP).Replace(".","-")).Replace(":","-"))'>
                        View $($_.IP)'s Attack Logs <span class='badge badge-danger'>$(($_.FailedLogs | Measure-Object).Count)</span></button>
                     "
        }

        if(($_.HitLogs | Measure-Object).Count -gt 0) {
            $html += "
                        <button class='btn btn-warning text-danger btn-sm mb-1 font-weight-bold float-right mx-1' type='button' data-toggle='collapse'
                        data-target='#IP$((($_.IP).Replace(".","-")).Replace(":","-"))_HitLogs' aria-expanded='false' aria-controls='IP$((($_.IP).Replace(".","-")).Replace(":","-"))_HitLogs'>
                        View $($_.IP)'s Hit Logs <span class='badge badge-danger'>$(($_.HitLogs | Measure-Object).Count)</span></button>
                     "
        }
        $html += "</div>"

        if(($_.FailedLogs | Measure-Object).Count -gt 0) {
            $html2 += "<div id='IP$((($_.IP).Replace(".","-")).Replace(":","-"))' class='collapse'>"
            $html2 += ConvertTo-HTMLTable ($_.FailedLogs | Select CreatedDateTime, UserDisplayName, UserPrincipalName, AppDisplayName, `
                        @{Name="IpAddress"; Expression={ 
                                if($settings.ProxyTable[$_.IpAddress].isProxy -eq "YES" -or $settings.ProxyTable[$_.IpAddress].Proxy -eq "yes") 
                                { $_.IpAddress = "<span class='text-danger font-weight-bold'>$($_.IpAddress) 
                                                ($($settings.ProxyTable[$_.IpAddress].ProxyType)$($settings.ProxyTable[$_.IpAddress].Type)) 
                                                <br>$($settings.ProxyTable[$_.IpAddress].'attack history')</span>" }
                                $_.IpAddress } },
                        ClientAppUsed, @{Name='Device'; Expression={ "<div class='table px-0' style='width:200px'>"
                                                                                $_.DeviceDetail.PSObject.Properties | % {
                                                                                    if($_.Value) {
                                                                                    "<div class='row border-bottom px-0 mx-0'>
                                                                                     <div class='col px-0 d-inline'>" + $_.Name + ":</div> 
                                                                                     <div class='col-8 px-0 text-right font-weight-bold d-inline'>" + $_.Value + "</div>
                                                                                     </div>"
                                                                                    }
                                                                                }
                                                                                "</div>"
                                                                              };
                                                                           },
                            @{Name='Location'; Expression={ "<div class='table px-0' style='width:120px'>"
                                                                                $_.Location.PSObject.Properties | % {
                                                                                    if($_.Value -and $_.Name -ne "geoCoordinates") {
                                                                                    "<div class='row border-bottom px-0 mx-0'>
                                                                                     <div class='col px-0 d-inline'>" + $_.Name + ":</div> 
                                                                                     <div class='col-10 px-0 text-right font-weight-bold d-inline'>" + $_.Value + "</div>
                                                                                     </div>"
                                                                                    }
                                                                                }
                                                                                "</div>"
                                                                              };
                                                                           }, 
                            RiskDetail, 
                            @{Name='Status';Expression={$_.Status.ErrorCode};}, 
                            RiskState)

            $html2 += "</div>"
            $html += $html2 -replace "<table", "<table id='IP$((($_.IP).Replace(".","-")).Replace(":","-"))_table'"
            $tablelist += "
                   `$('#IP$((($_.IP).Replace(".","-")).Replace(":","-"))_table').DataTable({
                   `'order': [[0,'desc']]});
                   `$('.dataTables_length').addClass('bs-select');"
        }
        

        if(($_.HitLogs | Measure-Object).Count -gt 0) {
            $html3 += "<div id='IP$((($_.IP).Replace(".","-")).Replace(":","-"))_HitLogs' class='collapse'>"
            $html3 += ConvertTo-HTMLTable ($_.HitLogs | Select CreatedDateTime, UserDisplayName, UserPrincipalName, AppDisplayName, `
                        @{Name="IpAddress"; Expression={ 
                                if($settings.ProxyTable[$_.IpAddress].isProxy -eq "YES" -or $settings.ProxyTable[$_.IpAddress].Proxy -eq "yes") 
                                { $_.IpAddress = "<span class='text-danger font-weight-bold'>$($_.IpAddress) 
                                                ($($settings.ProxyTable[$_.IpAddress].ProxyType)$($settings.ProxyTable[$_.IpAddress].Type)) 
                                                <br>$($settings.ProxyTable[$_.IpAddress].'attack history')</span>" }
                                $_.IpAddress } },
                        ClientAppUsed, @{Name='Device'; Expression={ "<div class='table px-0' style='width:200px'>"
                                                                                $_.DeviceDetail.PSObject.Properties | % {
                                                                                    if($_.Value) {
                                                                                    "<div class='row border-bottom px-0 mx-0'>
                                                                                     <div class='col px-0 d-inline'>" + $_.Name + ":</div> 
                                                                                     <div class='col-8 px-0 text-right font-weight-bold d-inline'>" + $_.Value + "</div>
                                                                                     </div>"
                                                                                    }
                                                                                }
                                                                                "</div>"
                                                                              };
                                                                           },
                            @{Name='Location'; Expression={ "<div class='table px-0' style='width:120px'>"
                                                                                $_.Location.PSObject.Properties | % {
                                                                                    if($_.Value -and $_.Name -ne "geoCoordinates") {
                                                                                    "<div class='row border-bottom px-0 mx-0'>
                                                                                     <div class='col px-0 d-inline'>" + $_.Name + ":</div> 
                                                                                     <div class='col-10 px-0 text-right font-weight-bold d-inline'>" + $_.Value + "</div>
                                                                                     </div>"
                                                                                    }
                                                                                }
                                                                                "</div>"
                                                                              };
                                                                           }, 
                            IsInteractive, ResourceDisplayName, RiskDetail, 
                            @{Name='RiskAg';Expression={$_.RiskLevelAggregated};}, 
                            @{Name='RiskRealtime';Expression={$_.RiskLevelDuringSignIn};}, RiskState)

            $html3 += "</div>"
            $html += $html3 -replace "<table", "<table id='IP$((($_.IP).Replace(".","-")).Replace(":","-"))_HitLogs_table'"
            $tablelist += "                
                   `$('#IP$((($_.IP).Replace(".","-")).Replace(":","-"))_HitLogs_table').DataTable({
                   `'order': [[0,'desc']]});
                   `$('.dataTables_length').addClass('bs-select');"
        }

        $html2 = $html3 = ""

        $html += "</div>"

        Write-Progress -Activity $global:floatMsg -CurrentOperation ("Generating report for $($_.IP).. DONE")
    }

    Write-Progress -Activity $global:floatMsg -CurrentOperation ("Generating report for Azure Risky Users.. ")
    if(($AzureRiskUsers | Measure-Object).Count -gt 0) {
        $html += "<div class='container-fluid mb-5'>"    
        $html += "<link rel='stylesheet' href='https://cdn.datatables.net/1.10.21/css/jquery.dataTables.min.css'>
                  <script src='https://cdn.datatables.net/1.10.21/js/jquery.dataTables.min.js'></script>"

        $riskhead = "<div id='Azure_head' class='button btn-warning text-danger py-1 px-1 font-weight-bold border border-secondary'>AzureAD Risky Sign-ins</div>"

        $html += $riskhead
        $html3 += "<div id='Azure_div' class='mb-5'>"
        $html3 += ConvertTo-HTMLTable ($AzureRiskUsers.Group | Select CreatedDateTime, UserDisplayName, UserPrincipalName, AppDisplayName, `
                    @{Name="IpAddress"; Expression={ 
                            if($settings.ProxyTable[$_.IpAddress].isProxy -eq "YES" -or $settings.ProxyTable[$_.IpAddress].Proxy -eq "yes") 
                            { $_.IpAddress = "<span class='text-danger font-weight-bold'>$($_.IpAddress) 
                                            ($($settings.ProxyTable[$_.IpAddress].ProxyType)$($settings.ProxyTable[$_.IpAddress].Type)) 
                                            <br>$($settings.ProxyTable[$_.IpAddress].'attack history')</span>" }
                            $_.IpAddress } },
                    ClientAppUsed, @{Name='Device'; Expression={ "<div class='table px-0' style='width:200px'>"
                                                                            $_.DeviceDetail.PSObject.Properties | % {
                                                                                if($_.Value) {
                                                                                "<div class='row border-bottom px-0 mx-0'>
                                                                                 <div class='col px-0 d-inline'>" + $_.Name + ":</div> 
                                                                                 <div class='col-8 px-0 text-right font-weight-bold d-inline'>" + $_.Value + "</div>
                                                                                 </div>"
                                                                                }
                                                                            }
                                                                            "</div>"
                                                                          };
                                                                       },
                        @{Name='Location'; Expression={ "<div class='table px-0' style='width:120px'>"
                                                                            $_.Location.PSObject.Properties | % {
                                                                                if($_.Value -and $_.Name -ne "geoCoordinates") {
                                                                                "<div class='row border-bottom px-0 mx-0'>
                                                                                 <div class='col px-0 d-inline'>" + $_.Name + ":</div> 
                                                                                 <div class='col-10 px-0 text-right font-weight-bold d-inline'>" + $_.Value + "</div>
                                                                                 </div>"
                                                                                }
                                                                            }
                                                                            "</div>"
                                                                          };
                                                                       }, 
                        IsInteractive, ResourceDisplayName, RiskDetail, 
                        @{Name='RiskAg';Expression={$_.RiskLevelAggregated};}, 
                        @{Name='RiskRealtime';Expression={$_.RiskLevelDuringSignIn};}, RiskState)

        $html3 += "</div>"
        $html += $html3 -replace "<table", "<table id='Azure_table'"
        $tablelist += "                
               `$('#Azure_table').DataTable({
               `'order': [[0,'desc']]});
               `$('.dataTables_length').addClass('bs-select');"
    }
    Write-Progress -Activity $global:floatMsg -CurrentOperation ("Generating report for Azure Risky Users.. DONE")

    $html += "<script>
        `$(document).ready(function () {
        $($tablelist)

        `$('[data-toggle=`"tooltip`"]').tooltip()
        });
        </script>"
    $html = $html -replace "class SignIn",""
    $html = $html -replace "<table","<div class=' table-responsive'><table class='table table-sm table-striped table-condensed table-hover mb-0'"
    $html = $html -replace "</table>","</table></div>"
    $html +="        <center>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▀▒▒▒▒▒▒▒▒▒▒▒▒▄▒▒▒▒▒▒▒▀▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;color:red;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span><span style='font-size:12px;line-height:107%;'>█▒▒▄▒▒▒▒▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒█▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;color:#FFC000;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span><span style='font-size:12px;line-height:107%;'>█▒▒▒▒▒▒▒▒▒▒▒▒▄█▄▄▒▒▄▒▒▒█▒▄▄▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;color:yellow;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span><span style='font-size:12px;line-height:107%;'>▄▄▄▄▄<span style='color:yellow;'>▒▒</span>█▒▒▒▒▒▒▀▒▒▒▒▀█▒▒▀▄▒▒▒▒▒█▀▀▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;color:#92D050;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span><span style='font-size:12px;line-height:107%;'>██▄▀██▄█▒▒▒▄▒▒▒▒▒▒▒██▒▒▒▒▀▀▀▀▀▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;color:#00B0F0;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span><span style='font-size:12px;line-height:107%;'>▀██▄▀██▒▒▒▒▒▒▒▒▀▒██▀▒▒▒▒▒▒▒▒▒▒▒▒▒▀██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;color:#2a00fa;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span><span style='font-size:12px;line-height:107%;'>▀████▒▀▒▒▒▒▄▒▒▒██▒▒▒▄█▒▒▒▒▄▒▄█▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;color:#9a00fa;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span><span style='font-size:12px;line-height:107%;'>▀█▒▒▒▒▄▒▒▒▒▒██▒▒▒▒▄▒▒▒▄▒▒▄▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄█▄▒▒▒▒▒▒▒▒▒▒▒▀▄▒▒▀▀▀▀▀▀▀▀▒▒▄▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒█▀▀█████████▀▀▀▀████████████▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒████▀▒▒███▀▒▒▒▒▒▒▀███▒▒▀██▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'><span style='font-size:12px;line-height:107%;'>&nbsp;</span></p>
        <p style='margin-top:0in;margin-right:0in;margin-bottom:.0001pt;margin-left:0in;line-height:107%;font-size:15px;'>&nbsp;</p>
        </center>"

    #Write-Progress -Activity $global:floatMsg -CurrentOperation ("Waiting for header.. ")
    #$str1 = ($jobArray | Wait-Job | Receive-Job)
    #$str2 = ($jobArray2 | Wait-Job | Receive-Job)
    #Write-Progress -Activity $global:floatMsg -CurrentOperation ("Waiting for header.. DONE")

    $html = $html -replace "#atRisk#", $str2
    $html = $html -replace "#underAttack#", $str1


    Write-Progress -Activity $global:floatMsg -CurrentOperation ("Saving report to file.. ")
    [System.Web.HttpUtility]::HtmlDecode($html) | Out-File $settings.ReportFile

    #$users.RiskLogs | ConvertTo-Html -Property CreatedDateTime, UserDisplayName, UserPrincipalName, AppDisplayName, IpAddress, ClientAppUsed, DeviceDetail, Location, IsInteractive, ResourceDisplayName, Status, TokenIssuerName, TokenIssuerType, ProcessingTimeInMilliseconds, RiskDetail, RiskLevelAggregated, RiskLevelDuringSignIn, RiskState, MfaDetail -Head $Header

}



function importLogs {
param(
    [Parameter(Mandatory)]
    [PSObject]$file
    )

    Add-Type -Assembly System.Web.Extensions
    $path = (Get-Location).Path + "\" + $file
    #Write-Host $path

    $json = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
    $json.MaxJsonLength = 1048576000 #1000mb as bytes, default is 2mb

    Write-Progress -Activity $global:floatMsg -CurrentOperation ("Loading data from file.. $($path)")
    
    $filedata = [System.IO.File]::ReadAllText($path) #Using default encoding
    $logs = $filedata | ConvertFrom-Json
    #$logs = $json.Deserialize($filedata, [PSCustomObject])
    $filedata = $null
    $json = $null


    #Break

    return $logs
}



function Main {

    Measure-Command {
    
    $logs = logsDump -file $settings.outfile -from $lastrun -limit $limit

    if($logs) {
        $threats = (ThreatsHunt $logs)

        $underAttackList =  (($threats.UnderAttackUsers | Select Name -Unique).Name)
        $atRiskList =  @($threats.atRiskUsers | Where {$_ -ne $null}  | Select -Unique)

        
        $AZRisk = (getAzureRisk $lastrun)
        $AZRiskList = @($AZRisk.Name | Where {$_ -ne $null}  | Select -Unique)

        $list = (($atRiskList + $AZRiskList) -join ",").Trim()

        exportReport $threats $AZRisk

        Write-Host $list
        SendReport
        
        #$PSScriptRoot 

        #$RunNyan = $PSScriptRoot+"\Nyan.ps1"

        #Write-Host "Sending list to Nyan.."
        #&$RunNyan "$list" -killEXO -inbox -samples 150 -Debug

    }

    }

}

Main