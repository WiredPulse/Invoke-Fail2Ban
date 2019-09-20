<#
.SYNOPSIS  
    Invoke-Faile2Ban is port of the *nix version of the original Fail2ban program. This script will monitor for a certain number of failed attempts and block to IP for a designated
    period of time. The blocked IPs are written to the Application log using a user-defined event source and ID. Additionally, those IPs are also stored in a queryable SQL db. The
    script will also whitelist the ip(s) of the system that is running the script and allows for other IPs to be whitelisted as well.

.EXAMPLE
    PS C:\> C:\<Path_to_script_folder>\invoke-fail2ban\invoke-fail2ban.ps1

.LINKS
    PSSQLITE -> https://github.com/RamblingCookieMonster/PSSQLite
    Fail2ban -> https://www.fail2ban.org/wiki/index.php/Main_Page
#>

Import-Module "$PSScriptRoot\PSSQLite\PSSQLite.psd1"

# =+=+=+=+=+=+=+=+=+=+=+=+=
# configs
    $fails = 3    # Number of fails before being banned
    $cycleDuration = 15     # Number of minutes between each failure check
    $startTime = 30     # Number of days to check logs for
    $banLength = 20     # Number of days to ban IPs for
    $eventSource = "Invoke-PSFail2Ban"     # Event source name within the Application log to log in Event Logs upon a ban being implemented
    $EventID = 1337     # Event log ID within the Application log to events under
    $script:whitelistDB = "$PSScriptRoot" + "\whitelist.SQLite"
    $script:BanDB = "$PSScriptRoot" + "\PSFail2Ban.SQLite"
# =+=+=+=+=+=+=+=+=+=+=+=+=

Function SingleEntry{
    Write-Host "##############################" -ForegroundColor Yellow
    Write-host -ForegroundColor Cyan "Whitelisting:"
    Write-Host " "
    write-host "This system's IP(s) will automatically be whitelisted. Do you want to whitelist any other IPs?"
    write-host " "
    Write-Host "[1] " -ForegroundColor cyan -NoNewline; write-host "Yes"
    Write-Host "[2] " -ForegroundColor cyan -NoNewline; write-host "No"
    $wlStart = Read-host " "
    if($wlStart -eq 1){
        write-host " "
        $Comp = Read-Host "Enter an IP (1.1.1.1) or IP Subnet (1.1.1.1/24) to whitelist"
        if ($Comp -eq $Null) { . SingleEntry } 
        elseIf ($Comp -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}"){
            $Temp = $Comp.Split("/")
            $IP = $Temp[0]
            $Mask = $Temp[1]
            . Get-Subnet-Range $IP $Mask
            $Script:Computers = $Script:IPList
            wl_add
        }
        else{ 
        $Script:Computers = $Comp
        }
    }
    elseif($wlStart -eq 2){
        #
    }
    else{
        Write-Host -ForegroundColor Red "Please enter either 1 or 2"
        pause
        SingleEntry
    } 
}

Function Get-Subnet-Range{      
    Param(
        [string]
        $IP,
        [string]
        $netmask
    )  

    $IPs = New-Object System.Collections.ArrayList

    Function Get-NetworkAddress{
        Param (
            [string]
            $IP,  
            [string]
            $Mask,
            [switch]
            $Binary
        )

        $NetAdd = $null

        $BinaryIP = ConvertTo-BinaryIP $IP
        $BinaryMask = ConvertTo-BinaryIP $Mask
        0..34 | foreach-object{
            $IPBit = $BinaryIP.Substring($_,1)
            $MaskBit = $BinaryMask.Substring($_,1)
            if($IPBit -eq '1' -and $MaskBit -eq '1'){
                $NetAdd = $NetAdd + "1"
            } 
            elseif ($IPBit -eq "."){
                $NetAdd = $NetAdd +'.'
            } 
            else{
                $NetAdd = $NetAdd + "0"
            }
        }

        if ($Binary){
            return $NetAdd
        } 
        else {
            return ConvertFrom-BinaryIP $NetAdd
        }  
    }
       
    Function ConvertTo-BinaryIP{
        Param (
            [string]
            $IP
        )

        $out = @()
        Foreach ($octet in $IP.split('.')) {
            $strout = $null
            0..7|ForEach-Object{
                if (($octet - [math]::pow(2,(7-$_)))-ge 0) {
                    $octet = $octet - [math]::pow(2,(7-$_))
                    [string]$strout = $strout + "1"
                } 
                else{
                    [string]$strout = $strout + "0"
                }  
            }
            $out += $strout
        }
        return [string]::join('.',$out)        
    }
 
 
    Function ConvertFrom-BinaryIP{
        Param (
            [string]
            $IP
        )

        $out = @()
        Foreach ($octet in $IP.split('.')) {
            $strout = 0
            0..7|foreach-object {
                $bit = $octet.Substring(($_),1)
                if ($bit -eq 1) {
                    $strout = $strout + [math]::pow(2,(7-$_))
                }
            }
            $out += $strout
        }
        return [string]::join('.',$out)  
    }

    Function ConvertTo-MaskLength {
        Param (
            [string]
            $mask
        )

        $out = 0
        Foreach ($octet in $Mask.split('.')) {
            #$strout = 0
            0..7|foreach-object {
                if (($octet - [math]::pow(2,(7-$_)))-ge 0){
                    $octet = $octet - [math]::pow(2,(7-$_))
                    $out++
                }
            }
        }
        return $out
        
    }
 
    Function ConvertFrom-MaskLength {
        Param (
            [int]
            $mask
        )

        $out = @()
        [int]$wholeOctet = ($mask - ($mask % 8))/8
        if ($wholeOctet -gt 0){
            1..$($wholeOctet) |ForEach-Object{
                $out += "255"
            }
        }
        $subnet = ($mask - ($wholeOctet * 8))
        if ($subnet -gt 0){
            $octet = 0
            0..($subnet - 1) | ForEach-Object{
                    $octet = $octet + [math]::pow(2,(7-$_))
            }
            $out += $octet
        }
        for ($i=$out.count;$i -lt 4; $I++){
            $out += 0
        }
        return [string]::join('.',$out)    
    }

    Function Get-IPRange {
        Param (
            [string]
            $IP,             
            [string]
            $netmask
        )

            if ($netMask.length -le 3){
                $masklength = $netmask.replace('/','')
                $Subnet = ConvertFrom-MaskLength $masklength
            } 
            else{
                $Subnet = $netmask
                $masklength = ConvertTo-MaskLength -Mask $netmask
            }
            $network = Get-NetworkAddress -IP $IP -Mask $Subnet
               
            [int]$FirstOctet,[int]$SecondOctet,[int]$ThirdOctet,[int]$FourthOctet = $network.split('.')
            $TotalIPs = ([math]::pow(2,(32-$masklength)) -2)
            $blocks = ($TotalIPs - ($TotalIPs % 256))/256
            if ($Blocks -gt 0){
                1..$blocks | ForEach-Object{
                    0..255 |ForEach-Object{
                        if ($FourthOctet -eq 255){
                            if ($ThirdOctet -eq 255){
                                if ($SecondOctet -eq 255){
                                    $FirstOctet++
                                    $secondOctet = 0
                                } 
                                else{
                                    $SecondOctet++
                                    $ThirdOctet = 0
                                }
                            } 
                            else{
                                $FourthOctet = 0
                                $ThirdOctet++
                            }  
                        } 
                        else{
                            $FourthOctet++
                        }
                        Write-Output ("{0}.{1}.{2}.{3}" -f `
                        $FirstOctet,$SecondOctet,$ThirdOctet,$FourthOctet)
                    }
                }
            }
            $sBlock = $TotalIPs - ($blocks * 256)
            if ($sBlock -gt 0){
                1..$SBlock | ForEach-Object{
                    if ($FourthOctet -eq 255){
                        if ($ThirdOctet -eq 255){
                            if ($SecondOctet -eq 255){
                                $FirstOctet++
                                $secondOctet = 0
                            } 
                            else{
                                $SecondOctet++
                                $ThirdOctet = 0
                            }
                        } 
                        else{
                            $FourthOctet = 0
                            $ThirdOctet++
                        }  
                    } 
                    else{
                        $FourthOctet++
                    }
                    Write-Output ("{0}.{1}.{2}.{3}" -f `
                    $FirstOctet,$SecondOctet,$ThirdOctet,$FourthOctet)
                }
            }
    }
    
    Get-IPRange $IP $netmask | ForEach-Object{
    [void]$IPs.Add($_)
    }
    $Script:IPList = $IPs
}

Function wl_check{
    if(-not(test-path $whitelistDB)){
        wl_create
        sysIP
        SingleEntry
    }
    else{
        Invoke-SqliteQuery -DataSource $whitelistDB -Query "SELECT * FROM whitelist" -As PSObject
        wl_prompt
    }

}

Function wl_prompt{
    Write-Host "##############################" -ForegroundColor Yellow
    Invoke-SqliteQuery -DataSource $whitelistDB -Query "SELECT * FROM whitelist" -As PSObject| out-host
    Write-host "A whitelist already exists with the above IP(s), which includes this systems IP(s).`nDo you want to continue to use it or create a new one?"
    write-host " "
    write-host "[1] " -ForegroundColor cyan -NoNewline; write-host "Create a new one"
    write-host "[2] " -ForegroundColor cyan -NoNewline; write-host "Use the current one"
    [int]$ans = read-host " "
    if($ans -eq 1){
        remove-item $whitelistDB
        wl_create 
        sysIP 
        SingleEntry 
    }
    elseif($ans -eq 2){
        #
    }
    else{
        Write-Host -ForegroundColor Red "Please enter either 1 or 2"
        pause
        wl_prompt
    }
}

Function wl_create{
    $Query = 'CREATE TABLE whitelist (
    ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
    IP TEXT,
    Added DATETIME)'

    Invoke-SqliteQuery -Query $Query -DataSource $whitelistDB | Out-Null
}

Function wl_add{
    $Query = 'INSERT INTO whitelist (IP, Added)
            VALUES (@IP, @Added)'

    foreach($item in $iplist){
        Invoke-SqliteQuery -DataSource $whitelistDB -Query $Query -SqlParameters @{
            IP = $item
            Added = get-date
        } | Out-Null  
    }
}

Function sysIP{
    $localIP = (Get-NetIPAddress).ipaddress

    $Query = 'INSERT INTO whitelist (IP, Added)
            VALUES (@IP, @Added)'

    foreach($item in $localIP){
        Invoke-SqliteQuery -DataSource $whitelistDB -Query $Query -SqlParameters @{
            IP = $item
            Added = get-date
        } | Out-Null 
    }
}

function ban_creation{
    if(-not(test-path $BanDB)){
        $Query = 'CREATE TABLE logger (
        BanID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        IP TEXT,
        Added DATETIME,
        Expiration DATETIME,
        Removed)'

        Invoke-SqliteQuery -Query $Query -DataSource $BanDB | Out-Null
    }
}

Function unban{
    $fw_list = (Get-NetFirewallRule).DisplayName
    foreach($fw in $fw_list){
        if($fw -like "ban_*"){
            Remove-NetFirewallRule -DisplayName $fw
            $date = get-date
            write-host "$($date.ToUniversalTime().tostring("dd-MMM-yy HH:mm:ss")) -- Ban_$banIP FW rule successfully deleted!" 
        }
    }
    write-host " "
    if(test-path $bandb){
        Remove-Item $bandb
        Write-Host -ForegroundColor Green "Banned IP db removed..."
    }

    write-host -ForegroundColor Green "All FW rules for banned IPs removed..."
    pause
    exit
}

write-host " "
write-host "###################################################################################" -ForegroundColor Yellow
write-host "     ____                 __              ______      _ _____   ____               " -ForegroundColor Cyan
write-host "    /  _/___ _   ______  / /_____        / ____/___ _(_) /__ \ / __ )____ _____  " -ForegroundColor Cyan
write-host "    / // __ \ | / / __ \/ //_/ _ \______/ /_  / __ ` / / /__/ // __ / __ `  / __ \  "-ForegroundColor Cyan
write-host "  _/ // / / / |/ / /_/ / ,< /  __/_____/ __/ / /_/ / / // __// /_/ / /_/ / / / /  "-ForegroundColor Cyan
write-host " /___/_/ /_/|___/\____/_/|_|\___/     /_/    \__,_/_/_//____/_____/\__,_/_/ /_/   "   -ForegroundColor Cyan
write-host " "                                                                     
write-host "###################################################################################" -ForegroundColor Yellow
write-host " "
write-host "[1] " -ForegroundColor Cyan -NoNewline; write-host "Start Monitoring"
write-host "[2] " -ForegroundColor Cyan -NoNewline; write-host "List Banned IPs & Status"
write-host "[3] " -ForegroundColor Cyan -NoNewline; write-host "List Whitelisted IPs"
write-host "[4] " -ForegroundColor Cyan -NoNewline; write-host "Unban All IPs"
$q = read-host " "
write-host " "
    if($q -eq 1){
        wl_check
        ban_creation
    }
    elseif($q -eq 2){
            Write-Host "##############################" -ForegroundColor Yellow
            Write-Host -ForegroundColor Cyan "Banned IPS & Status:"
            Invoke-SqliteQuery -DataSource $BanDB -Query "SELECT * FROM logger" | out-host
            pause
            break
    }
    elseif($q -eq 3){
        Write-Host "##############################" -ForegroundColor Yellow
        Write-Host -ForegroundColor Cyan "Whitelisted IPs:"
        Invoke-SqliteQuery -DataSource $whitelistDB -Query "SELECT * FROM whitelist" | out-host
        pause
        break
    }
    else{
        unban
    }

Write-Host " "
Write-Host "##############################" -ForegroundColor Yellow
Write-Host -ForegroundColor Cyan "Whitelisted IPs:"
Invoke-SqliteQuery -DataSource $whitelistDB -Query "SELECT * FROM whitelist" -As PSObject| out-host
pause

Write-Host -ForegroundColor Green "$((get-date).ToUniversalTime().tostring("dd-MMM-yy HH:mm:ss")) -- Invoke-Fail2Ban is monitoring"
Write-Host " "

New-EventLog -LogName application -Source $eventSource -ErrorAction SilentlyContinue
    if($? -eq $true){
        New-EventLog -LogName application -Source $eventSource -ErrorAction SilentlyContinue
    }

$WlCurrent = (Invoke-SqliteQuery -DataSource $whitelistdb -Query "SELECT * FROM whitelist" -As PSObject).ip

while($true)
{
    $start = (get-date).AddSeconds(-$startTime)
    try{
    $events = Get-WinEvent -FilterHashtable @{logname='security';id='4625';starttime=$start;endtime=$(get-date)} -ErrorAction stop | Select-Object @{label="IP";expression={$_.properties.value[19]}}
    }catch{ }
    $count =  $events | Group-Object -Property IP
    $ip = $count | Select-Object count, name | Sort-Object count | Where-Object{$_.count -ge $fails -and $_.name -ne '-'}
        foreach($sys in $ip.name){
            if(-not($wlCurrent.Contains("$sys"))){   
                $ruleName = "Ban_" + $sys

                try{
                    Get-NetFirewallRule -DisplayName "$ruleName" -ErrorAction stop| out-null
                }
                catch{
                    New-NetFirewallRule -displayname "$ruleName" -direction "in" -Action "block" -Protocol "tcp" -RemoteAddress "$sys" -ErrorAction SilentlyContinue | out-null
                        if(Get-NetFirewallRule -DisplayName "$ruleName"){
                            $banExpiration = (Get-Date).AddSeconds($banLength)
                            write-host -ForegroundColor cyan "$((get-date).ToUniversalTime().tostring("dd-MMM-yy HH:mm:ss")) -- Ban_$sys FW rule successfully added!"
                            Write-EventLog -LogName application -Source $eventSource -EntryType Warning -EventId $EventID -Message "Blocked IP: $sys`nBlock Expiration: $banExpiration`nFW Rule: $rulename"
                        }
                        else{
                            write-host -ForegroundColor Red "ERROR: FW rule couldn't be created for $sys"
                        }

                    $Query = 'INSERT INTO logger (IP, Added, Expiration, Removed)
                        VALUES (@IP, @Added, @Expiration, @Removed)'

                    Invoke-SqliteQuery -DataSource $BanDB -Query $Query -SqlParameters @{
                        IP = $sys
                        Added = $date
                        Expiration = $banExpiration
                        Removed = "N"
                    } | Out-Null
                }
            }
            }

    try{
    $list = Invoke-SqliteQuery -DataSource $BanDB -Query "SELECT * FROM logger" -As PSObject -ErrorAction stop
    }
    catch{ #
    }
    if($list -ne $null){
        foreach($item in $list){
            if($item.expiration -lt (get-date) -and $item.removed -eq "N"){
                $banIP = ($item).ip
                Invoke-SqliteQuery -DataSource $BanDB -Query "UPDATE logger SET Removed='Y' where IP='$banIP'" -As PSObject
                Remove-NetFirewallRule -DisplayName "Ban_$banIP"
                    if(-not(Remove-NetFirewallRule -DisplayName "Ban_$banIP" -ErrorAction SilentlyContinue)){
                        write-host -ForegroundColor yellow "$((get-date).ToUniversalTime().tostring("dd-MMM-yy HH:mm:ss")) -- Ban_$banIP FW rule successfully deleted due to time expiration!"
                    } 
                }
            }
        } 
    Start-Sleep -Seconds $cycleDuration
    write-host -ForegroundColor Green "$((get-date).ToUniversalTime().tostring("dd-MMM-yy HH:mm:ss")) -- Invoke-Fail2Ban is monitoring"
}