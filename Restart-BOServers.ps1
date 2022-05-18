try {
    # Replace in Azure DevOps
    $SelectedStages = $env:STAGES.Split(',')

    # Which serers are in which stage
    $Prod = @("W17003", "W17004", "W17005", "W17006")
    $Stage = @("W17001", "W17002")
    $Dev = @("W16999")
    $Sandbox = @("W17000")

    # Make hashmap of stages
    $Stages = @{
        "prod"    = $Prod;
        "stage"   = $Stage;
        "dev"     = $Dev;
        "sandbox" = $Sandbox
    }

    # Create array of computers to restart
    $Computers = @()
    ($SelectedStages -contains "prod"    ? ($Computers += $Prod)    : $null) | Out-Null
    ($SelectedStages -contains "stage"   ? ($Computers += $Stage)   : $null) | Out-Null
    ($SelectedStages -contains "dev"     ? ($Computers += $Dev)     : $null) | Out-Null
    ($SelectedStages -contains "sandbox" ? ($Computers += $Sandbox) : $null) | Out-Null    
    
    # Add each computer to the trusted hosts list for WinRM
    foreach ($Computer in $Computers) {
        if ((Get-Item WSMan:\\localhost\client\TrustedHosts).Value -notlike "*$Computer* ") {
            Set-Item WSMan:\\localhost\client\TrustedHosts -Value "$Computer" -Concatenate -Force
        }
    }

    $AppdPassword = $env:APPDPASSWORD

    # List of which computers failed to start
    $FailedRestarts = $()
    foreach ($Computer in $Computers) {
        # Get credential for the bo-admin account for the lane the computer is on
        switch ("prod", "stage", "dev", "sandbox" | Where-Object { $Stages[$_] -contains $Computer }) {
            "prod" {
                $Pswd = ConvertTo-SecureString -String $env:BOADMIN -AsPlaintext -Force
                $Cred = [System.Management.Automation.PSCredential]::new("boadmin", $Pswd)
                break
            }
            "stage" {
                $Pswd = ConvertTo-SecureString -String $env:BO_ADMIN_STAGE -AsPlaintext -Force
                $Cred = [System.Management.Automation.PSCredential]::new("bo-admin-stage", $Pswd)
                break
            }
            "dev" {
                $Pswd = ConvertTo-SecureString -String $env:BO_ADMIN_DEV -AsPlaintext -Force
                $Cred = [System.Management.Automation.PSCredential]::new("bo-admin-dev", $Pswd)
                break
            }
            "sandbox" {
                $Pswd = ConvertTo-SecureString -String $env:BO_ADMIN_TEST -AsPlaintext -Force
                $Cred = [System.Management.Automation.PSCredential]::new("bo-admin-test", $Pswd)
                break
            }
        }

        # Controls whether to begin restart process 
        $NeedsRestart = $true
        # Don't restart more than 5 times
        $NumRestarts = 0
        while ($NeedsRestart -and $NumRestarts -lt 3) {
            Write-Host "[$(Get-Date)] Beginning restart attempt $($NumRestarts + 1) for server $Computer"

            Invoke-Command -ComputerName $Computer -Credential $Cred -SessionOption (New-PSSessionOption -IncludePortInSPN) {
                param($Computer)

                Write-Host "[$(Get-Date)] Triggering restart on server $Computer"
                shutdown /r /t 0
            } -ArgumentList $Computer

            $SleepFor = 45
            Write-Host "[$(Get-Date)] Sleeping for $SleepFor seconds while $Computer restarts"
            Start-Sleep -Seconds $SleepFor

            Write-Host "[$(Get-Date)] Starting PSSession to server $Computer"
            # Just because the server has restarted doesn't mean it's ready to connect to, so try to connect up to 5 times
            $Attempts = 0
            try {
                while ($Attempts -lt 5) {
                    try {
                        $Session = New-PSSession -ComputerName $Computer -Credential $Cred -SessionOption (New-PSSessionOption -IncludePortInSPN)
                        # If connection was successful, move on.
                        break
                    }
                    catch {
                        if ($_ -match "^\[.{0,6}\] Connecting to remote server .{0,6} failed with the following error message : .*$") {
                            $Attempts++
                            Write-Host "[$(Get-Date)] Failed attempts to start PSSession to server $($Computer): $Attempts"
                            # Wait an increasing amount of time between connects
                            Start-Sleep -Seconds (($Attempts) * 5)
                            continue
                        }
                        else {
                            throw $_
                        }
                    }
                }
            }
            catch {
                Write-Host "[$(Get-Date)] Unhandled error occured while starting PSSession to server $($Computer): $_"
                continue
            }

            $NeedsRestart = invoke-command -Session $Session -ScriptBlock {
                param($Computer, $AppdPassword)
                try {
                    # Begin supporting classes and functions
                    class BOService {
                        [string]$ServerName
                        [string]$ServiceName
                        [string]$State
                        [string]$Status
                        [string]$ProcessId
                        [string]$CommandName
                    
                        BOService(
                            [string]$ServerName,
                            [string]$ServiceName,
                            [string]$State,
                            [string]$Status,
                            [string]$ProcessId
                        ) {
                            $this.ServerName = $ServerName
                            $this.ServiceName = $ServiceName
                            $this.State = $State
                            $this.Status = $Status
                            $this.ProcessId = $ProcessId
                            $this.CommandName = "$ServerName.$ServiceName"
                        }
                    }
                
                    class BOInstance {
                        [string]$ExeLocation
                        [string]$Username
                        [string]$Password
                        [string]$Authentication
                        [BOService[]]$Services
                        [string[]]$ExcludedServices = , "CentralManagementServer"
                        [string]$LogLevel = "Error"
                        static [string]$LogFolder = "C:\temp\BO_Service_Management\"
                        static [string]$LogName = "$((Get-Date).ToShortDateString().replace('/','-'))_BO_Service_Management.txt"
                    
                        BOInstance(
                            [string]$ExeLocation,
                            [string]$Username,
                            [string]$Password,
                            [string]$Authentication
                        ) {
                            [BOInstance]::CleanLogs()
                            $LogLoc = "Constructor"
                            $this.LogDebug($LogLoc, "Instanciated using 4 parameter constructor")
                            $this.LogDebug($LogLoc, "Parameter `"ExeLocation`" is `"$ExeLocation`"")
                            $this.LogDebug($LogLoc, "Parameter `"Username`" is `"$Username`"")
                            $this.LogDebug($LogLoc, "Parameter `"Password`" is not disclosed")
                            $this.LogDebug($LogLoc, "Parameter `"Authentication`" is `"$Authentication`"")
                            $this.ExeLocation = $ExeLocation
                            $this.Username = $Username
                            $this.Password = $Password
                            $this.Authentication = $Authentication
                            $this.CheckServer()
                            $this.LogInfo($LogLoc, "Parameters validated successfully")
                            $this.UpdateServices()
                        }
                
                        BOInstance(
                            [string]$Password
                        ) {
                            [BOInstance]::CleanLogs()
                            $LogLoc = "Constructor"
                            $this.LogDebug($LogLoc, "Instanciated using 1 parameter constructor")
                            $this.LogDebug($LogLoc, "Parameter `"Password`" is not disclosed")
                            $this.ExeLocation = "F:\BusinessObjects\SAP BusinessObjects Enterprise XI 4.0\win64_x64\ccm.exe"
                            $this.Username = "appd_monitoring"
                            $this.Authentication = "secEnterprise"
                            $this.Password = $Password
                            $this.CheckServer()
                            $this.LogInfo($LogLoc, "Parameters validated successfully")
                            $this.UpdateServices()
                        }
                
                
                        [void]CheckServer() {
                            $LogLoc = "CheckServer"
                            try {
                                $CorrectParams = (& $this.ExeLocation -Display -Username $this.Username -Password $this.Password -Authentication $this.Authentication)
                            }
                            catch {
                                $this.LogCritical($LogLoc, "Parameter `"ExeLocation`" is invalid. Terminating.")
                                throw "Parameter `"ExeLocation`" is incorrect or insuficcient permissions were used."
                            }
                            if ($CorrectParams[2].StartsWith("Unable")) {
                                $this.LogCritical($LogLoc, "$($CorrectParams[2]): $($CorrectParams[3])")
                                throw "$($CorrectParams[2]): $($CorrectParams[3])"
                            }
                        }
                
                        [BOService]StartService([BOService]$Service) {
                            $LogLoc = "StartService"
                            $this.LogDebug($LogLoc, "Starting service `"$($Service.ServiceName)`" on host `"$($Service.ServerName)`" with status `"$($Service.Status)`" and state `"$($Service.State)`"")
                            $this.SendRawCommand("-managedstart", $Service.CommandName)
                            Start-Sleep -Seconds 5
                            return $this.UpdateServices($Service)
                        }
                
                        [BOService]StopService([BOService]$Service) {
                            $LogLoc = "StopService"
                            $this.LogDebug($LogLoc, "Stopping service `"$($Service.ServiceName)`" on host `"$($Service.ServerName)`" with status `"$($Service.Status)`" and state `"$($Service.State)`"")
                            $this.SendRawCommand("-managedstop", $Service.CommandName)
                            return $this.UpdateServices($Service)
                        }
                
                        [BOService]EnableService([BOService]$Service) {
                            $LogLoc = "EnableService"
                            $this.LogDebug($LogLoc, "Enabling service `"$($Service.ServiceName)`" on host `"$($Service.ServerName)`" with status `"$($Service.Status)`" and state `"$($Service.State)`"")
                            $this.SendRawCommand("-enable", $Service.CommandName)
                            return $this.UpdateServices($Service)	
                        }
                
                        [BOService]DisableService([BOService]$Service) {
                            $LogLoc = "DisableService"
                            $this.LogDebug($LogLoc, "Disabling service `"$($Service.ServiceName)`" on host `"$($Service.ServerName)`" with status `"$($Service.Status)`" and state `"$($Service.State)`"")
                            $this.SendRawCommand("-disable", $Service.CommandName)
                            return $this.UpdateServices($Service)
                        }
                
                        [void]RestartService([BOService]$Service) {
                            $LogLoc = "RestartService"
                            $this.LogInfo($LogLoc, "Beginning restart of service $($Service.CommandName)")
                            $Service = $this.DisableService($Service)
                            $Service = $this.StopService($Service)
                            $Service = $this.StartService($Service)
                            $FailCount = 0
                            while (-not $Service.State -like "Running*" -and $FailCount -lt 12) {
                                Start-Sleep -Seconds 5
                                $Service = $this.UpdateServices($Service)
                                $FailCount++
                                if ($FailCount -lt 12) {
                                    $this.LogError($LogLoc, "Service `"$($Service.CommandName)`" has not entered running state after $($FailCount * 5) seconds")
                                }
                                else {
                                    $this.LogCritical($LogLoc, "Service `"$($Service.CommandName)`" has not entered running state after $($FailCount * 5) seconds")
                                }
                            }
                            $Service = $this.EnableService($Service)
                            $FailCount = 0
                            while ($Service.Status -ne "Enabled" -and $FailCount -lt 12) {
                                $Service = $this.EnableService($Service)
                                Start-Sleep -Seconds 5
                                $FailCount++
                                if ($FailCount -lt 12) {
                                    $this.LogError($LogLoc, "Service `"$($Service.CommandName)`" has not changed to enabled status after $($FailCount * 5) seconds")
                                }
                                else {
                                    $this.LogCritical($LogLoc, "Service `"$($Service.CommandName)`" has not changed to enabled status after $($FailCount * 5) seconds")
                                }
                            }
                            $this.LogInfo($LogLoc, "End of restart of service $($Service.CommandName)")
                            $this.LogDebug($LogLoc, "Status was `"$($Service.Status)`" and state was `"$($Service.State)`"")
                        }
                
                        [void]RestartServices([object[]]$CommandNames) {
                            $LogLoc = "RestartServices"
                            $this.LogInfo($LogLoc, "Attempting to restart the following services: $($CommandNames -Join ", ")")
                            foreach ($CommandName in $CommandNames) {
                                [BOService]$Service = $this.Services | Where-Object { $_.CommandName -eq $CommandName }
                                $this.RestartService($Service)
                            }
                        }
                
                        [void]RestartAllServices() {
                            $LogLoc = "RestartAllServices"
                            $this.LogInfo($LogLoc, "Triggering a restart of all services")
                            $this.RestartServices($this.Services.CommandName)
                        }
                
                        [void]RestartServices([string]$ComputerName) {
                            $LogLoc = "RestartServices"
                            $this.LogInfo($LogLoc, "Triggering a restart of all services on host `"$ComputerName`"")
                            $this.RestartServices(($this.Services | Where-Object { $_.ServerName -eq $ComputerName }).CommandName)
                        }
                
                        [BOService]UpdateServices([BOService]$Service) {
                            $LogLoc = "UpdateServices"
                            $this.LogInfo($LogLoc, "Triggering an update of services to refresh service `"$($Service.CommandName)`"")
                            $CommandName = $Service.CommandName
                            $this.UpdateServices()
                            return $this.Services | Where-Object { $_.CommandName -like $CommandName }
                        }
                
                        [void]UpdateServices() {
                            $LogLoc = "UpdateServices"
                            $this.LogInfo($LogLoc, "Updating services")
                            [string[]]$RawServices = $this.GetRawDetails()
                            [BOService[]]$this.Services = $null
                            foreach ($i in 0..($RawServices.Count - 1)) {
                                if ($RawServices[$i].StartsWith("Server Name:")) {
                                    $this.LogDebug($LogLoc, "Service found in raw text")
                                    $ServerName = $RawServices[$i + 3].Split(':', 2)[1].Trim()
                                    $ServiceName = $RawServices[$i].Split('.', 2)[1].Trim()
                                    $this.LogDebug($LogLoc, "Host name is `"$ServerName`"")
                                    $this.LogDebug($LogLoc, "Service name is `"$ServiceName`"")
                                    if ($ServiceName -in $this.ExcludedServices) {
                                        $this.LogDebug($LogLoc, "Because `"$ServiceName`" is in the excluded list, it will not be tracked")
                                        continue
                                    }
                                    $State = $RawServices[$i + 1].Split(':', 2)[1].Trim()
                                    $this.LogDebug($LogLoc, "State is `"$State`"")
                                    $Status = $RawServices[$i + 2].Split(':', 2)[1].Trim()
                                    $this.LogDebug($LogLoc, "Status is `"$Status`"")
                                    $ProcessId = $null
                                    if ($state.Equals("Running")) {
                                        $ProcessId = $RawServices[$i + 4].Split(':', 2)[1].Trim()
                                    }
                                    $this.LogDebug($LogLoc, "PID is `"$ProcessId`"")
                                    $NewService = [BOService]::new($ServerName, $ServiceName, $State, $Status, $ProcessId)
                                    $this.Services += $NewService
                                }
                            }
                            $this.LogInfo($LogLoc, "Update finished")
                        }
                
                        [BOService[]]ValidateServices() {
                            $LogLoc = "ValidateServices"
                            $this.LogInfo($LogLoc, "Started validating services")
                            $this.UpdateServices()
                            $this.LogInfo($LogLoc, "Finished validating services")
                            return $this.Services | Where-Object { $_.State -notlike 'Running*' -or $_.Status -ne "Enabled" }
                        }
                
                        [string[]]GetRawDetails() {
                            return $this.SendRawCommand("-Display")
                        }
                
                        [object]SendRawCommand([string]$Command, [string]$Data) {
                            $LogLoc = "SendRawCommand"
                            $FullCommand = "$($this.ExeLocation) $Command $Data -Username $($this.Username) -Password CONFIDENTIAL -Authentication $($this.Authentication)"
                            $this.LogInfo($LogLoc, "Running command: $FullCommand")
                            return & $this.ExeLocation $Command $Data -Username $this.Username -Password $this.Password -Authentication $this.Authentication
                        }
                
                        [object]SendRawCommand([string]$Command) {
                            return $this.SendRawCommand($Command, $null)
                        }
                
                        [void]Log([string]$From, [string]$Level, [string]$Message) {
                            if (!$(Test-Path )){
                                New-Item -Path $([BOInstance]::LogFolder) -ItemType Directory
                            }
                            "[$(Get-Date)][$From][$level] $Message" | Add-Content "$([BOInstance]::LogFolder)$([BOInstance]::LogName)"
                
                        }
                
                        [void]LogCritical([string]$From, [string]$Message) {
                            if ([int][LogLevels]$this.LogLevel -ge [int][LogLevels]"Critical") {
                                $this.Log($From, "Critical", $Message)
                            }
                        }
                
                        [void]LogError([string]$From, [string]$Message) {
                            if ([int][LogLevels]$this.LogLevel -ge [int][LogLevels]"Error") {
                                $this.Log($From, "Error", $Message)
                            }
                        }
                
                        [void]LogInfo([string]$From, [string]$Message) {
                            if ([int][LogLevels]$this.LogLevel -ge [int][LogLevels]"Info") {
                                $this.Log($From, "Info", $Message)
                            }
                        }
                
                        [void]LogDebug([string]$From, [string]$Message) {
                            if ([int][LogLevels]$this.LogLevel -ge [int][LogLevels]"Debug") {
                                $this.Log($From, "Debug", $Message)
                            }
                        }
                
                        static [void]CleanLogs() {
                            $LogFiles = Get-ChildItem -Path ([BOInstance]::LogFolder) -ErrorAction SilentlyContinue
                            foreach ($LogFile in $LogFiles) {
                                $LogDate = [Datetime]::Parse($LogFile.Name.Split('_', 2)[0])
                                if ((New-TimeSpan -Start $LogDate -End (Get-Date)).Days -gt 31) {
                                    Remove-Item $LogFile
                                }
                            }
                        }
                    }
                
                    enum LogLevels {
                        Critical = 0
                        Error = 20
                        Information = 40
                        Debug = 60
                    }
                
                    function Start-BOServices {
                        param (
                            [string[]]$Services
                        )
                
                        $BOServices = "Apache Tomcat for BI 4", "Server Intelligence Agent ($env:COMPUTERNAME )"
                        if ($Services -eq $null) {
                            $Services = $BOServices
                        }
                        else {
                            $Services = $Services | Where-Object { $_ -in $BOServices }
                        }
                
                        foreach ($Service in $Services) {
                            #restart it
                            $Service | Restart-Service
                        }
                    }
                
                    function Get-BOServices {
                        return Get-Service "Apache Tomcat for BI 4", "Server Intelligence Agent ($env:computername)" | Select-Object DisplayName, Status
                    }
                    # End supporting classes and functions

                    # Get and make sure the BO windows services are running
                    $Attempts = 0
                    $WinServices = Get-BOServices
                    Write-Host "[$(Get-Date)] Starting Windows services on server $Computer"
                    while ($Attempts -lt 8 -and ($WinServices | Where-Object { $_.Status -ne "Running" }).Count -gt 0) {
                        # Only attempt to start services that aren't running or will start
                        foreach ($WinService in ($WinServices | Where-Object { $_.Status -notin "Running", "StartPending" })) {
                            Start-BOServices -Services $WinService.DisplayName
                        }

                        # If service has start pending, wait for it
                        $WinServices = Get-BOServices
                        if (($WinServices | Where-Object { $_.Status -eq "StartPending" }).Count -gt 0) { 
                            Start-Sleep -Seconds ($Attempts * 5)
                        }

                        $WinServices = Get-BOServices
                        $Attempts++
                        Write-Host "[$(Get-Date)] Failed attempts to start Windows services on server $($Computer): $Attempts"
                    }

                    # Determine if any services aren't running
                    $BadServices = $WinServices | Where-Object { $_.Status -ne "Running" }
                    if ($BadServices.Count -gt 0) {
                        Write-Host "[$(Get-Date)] One or more Windows services on failed to start on server $($Computer): $($BadServices.DisplayName -join ", ")"
                        return $true
                    }
                    else {
                        Write-Host "[$(Get-Date)] Windows services started successfully on server $Computer."
                    }

                    # Instanciate and connect to the BO app to verify connection info and connectability
                    Write-Host "[$(Get-Date)] Starting connection to BO app on server $Computer"
                    $Attempts = 0
                    while ($attempts -lt 6) {
                        try {
                            $BOServer = [BOInstance]::new($AppdPassword)
                            # Connection successful, don't try to connect again
                            break
                        }
                        catch {
                            if ($_ -like "Unable to logon to CMS: Reason: Unable to log on: Could not connect to server*") {
                                $Attempts++
                                Write-Host "[$(Get-Date)] Failed attempts to connect to BO app on server $($Computer): $Attempts"
                            
                                # Wait an increasing amount of time before trying again
                                Start-Sleep -Seconds ($Attempts * 5)
                                continue
                            }
                            else {
                                # Not a recognized error, try restart process again
                                return $true
                            }
                        }   
                    }

                    if ($Attempts -eq 6) {
                        # Couldn't connect
                        Write-Host "[$(Get-Date)] Failed to connect to BO app on server $Computer"
                        return $true
                    }
                    else {
                        # Did connect 
                        Write-Host "[$(Get-Date)] Successfully connected to BO app on server $Computer"
                    }

                    # It made more sense to give the BO app a minute to start up its own servers before manually attempting to
                    $SleepFor = 90
                    Write-Host "[$(Get-Date)] Sleeping for $SleepFor seconds while BO app $Computer initializes services"
                    Start-Sleep -Seconds $SleepFor

                    $Attempts = 0
                    # Creates a log on the server which stores information about the BO service process. See the BOInstance class to see whats logged and where
                    $BOServer.LogLevel = "Error"
                
                    # Restart BO services that aren't running or enabled
                    Write-Host "[$(Get-Date)] Starting validation of BO services on server $Computer"
                    while ($Attempts -lt 3 -and ($BOServer.ValidateServices() | Where-Object { $_.ServerName -eq $env:COMPUTERNAME }).Count -gt 0) {
                        $BOServer.RestartServices(@(($BOServer.ValidateServices() | Where-Object { $_.ServerName -eq $env:COMPUTERNAME }).CommandName))
                        $Attempts++
                        Write-Host "[$(Get-Date)] Attempts to start BO services on server ${$Computer}: $Attempts"
                    }

                    $BadServices = $BOServer.ValidateServices() | Where-Object { $_.ServerName -eq $env:COMPUTERNAME }
                    foreach ($Service in $BadServices) {
                        Write-Host "[$(Get-Date)] Failed to start BO service `"$($Service.CommandName)`" which has a state of `"$($Service.State)`" and a status of `"$($Service.Status)`""
                    }

                    if ($BadServices.count -gt 0) {
                        # One or more BO services are either not running or disabled
                        return $true
                    }
                    else {
                        # All BO services started successfully
                        Write-Host "[$(Get-Date)] All BO services on server $Computer are running"
                        return $false
                    }
                }
                catch {
                    # If some unplanned error happens, attempt another restart
                    Write-Host "[$(Get-Date)] Unexpected error occured in connection to server $($Computer): $_"
                    return $true
                }
            } -ArgumentList $Computer, $AppdPassword

            Write-Host "[$(Get-Date)] Terminating PSSession to server $Computer" 
            Remove-PSSession $Session
            $NumRestarts++

            if ($NumRestarts -eq 3) {
                $FailedRestarts += $Computer
            }
        }
    }

    # Report back status at end of process
    if ($FailedRestarts.Count -gt 0) {
        Write-Host "[$(Get-Date)] The following servers failed to restart: $($FailedRestarts -join ", ")"
    }
    else {
        Write-Host "[$(Get-Date)] All specified server restarted sucessfully"
    }

    foreach ($Computer in $Computers) {
        Set-Item WSMan:\\localhost\client\TrustedHosts -Value $(((Get-Item WSMan:\\localhost\client\TrustedHosts).Value.Split(',') | where { $_ -ne $Computer }) -join ',') -Force
    }
        
}
catch {
    $detailedError = $_
    Write-Host "##vso[task.logissue type=error]$detailedError"
    Write-Host "##vso[task.complete result=Failed;]Script execution failed: $detailedError"
}