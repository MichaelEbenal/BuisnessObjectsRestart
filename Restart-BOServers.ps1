try {
    # Replace in Azure DevOps
    $SelectedLanes = $env:LANES.Split(',')

    # Which serers are in which stage
    $Prod    = @('W17003', 'W17004', 'W17005', 'W17006')
    $Stage   = @('W17001', 'W17002')
    $Dev     = @('W16999')
    $Sandbox = @('W17000')

    # Make hashmap of stages
    $Lanes = @{
        'prod'    = $Prod;
        'stage'   = $Stage;
        'dev'     = $Dev;
        'sandbox' = $Sandbox
    }

    # Create array of computers to restart
    $Computers = @()
    ($SelectedLanes -contains 'prod'    ? ($Computers += $Prod)    : $null) | Out-Null
    ($SelectedLanes -contains 'stage'   ? ($Computers += $Stage)   : $null) | Out-Null
    ($SelectedLanes -contains 'dev'     ? ($Computers += $Dev)     : $null) | Out-Null
    ($SelectedLanes -contains 'sandbox' ? ($Computers += $Sandbox) : $null) | Out-Null    
    
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
        switch ('prod', 'stage', 'dev', 'sandbox' | Where-Object { $Lanes[$_] -contains $Computer }) {
            'prod' {
                $Pswd = ConvertTo-SecureString -String $env:BOADMIN -AsPlaintext -Force
                $Cred = [System.Management.Automation.PSCredential]::new('boadmin', $Pswd)
                break
            }
            'stage' {
                $Pswd = ConvertTo-SecureString -String $env:BO_ADMIN_STAGE -AsPlaintext -Force
                $Cred = [System.Management.Automation.PSCredential]::new('bo-admin-stage', $Pswd)
                break
            }
            'dev' {
                $Pswd = ConvertTo-SecureString -String $env:BO_ADMIN_DEV -AsPlaintext -Force
                $Cred = [System.Management.Automation.PSCredential]::new('bo-admin-dev', $Pswd)
                break
            }
            'sandbox' {
                $Pswd = ConvertTo-SecureString -String $env:BO_ADMIN_TEST -AsPlaintext -Force
                $Cred = [System.Management.Automation.PSCredential]::new('bo-admin-test', $Pswd)
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
                        $Session = New-PSSession -ComputerName $Computer -Credential $Cred -SessionOption (New-PSSessionOption -IncludePortInSPN) -ErrorAction Stop
                        # If connection was successful, move on.
                        break
                    }
                    catch {
                        if ($_ -match '^\[.{0,6}\] Connecting to remote server .{0,6} failed with the following error message : .*$') {
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

            Write-Host "[$(Get-Date)] Triggering stop and delayed start of AppD monitoring agent."
            Invoke-Command -Session $Session -ScriptBlock {
                Start-ScheduledTask -TaskName 'Start AppD service after delay' -TaskPath '\PlatformTeam\'
                Stop-Service 'Appdynamics Machine Agent' -Force
            }

            $NeedsRestart = Invoke-Command -Session $Session -ScriptBlock {
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


                    class BORestartInstruction {
                        [string]$ServiceName
                        [string]$ServiceInstruction

                        BORestartInstruction(
                            [string]$ServiceName,
                            [string]$ServiceInstruction
                        ) {
                            $this.ServiceName = $ServiceName
                            $this.ServiceInstruction = $ServiceInstruction
                        }
                    }

                    class BOSpecialCaseRestart {
                        [string]$ServiceName
                        [string]$SpecialCase
                        [BORestartInstruction[]]$Instructions

                        BOSpecialCaseRestart(
                            [string]$ServiceName,
                            [string]$SpecialCase,
                            [BORestartInstruction[]]$Instructions
                        ) {
                            $this.ServiceName = $ServiceName
                            $this.SpecialCase = $SpecialCase
                            $this.Instructions = $Instructions
                        }
                    }
                    
                    enum LogLevels {
                        Critical = 0
                        Error = 20
                        Information = 40
                        Debug = 60
                    }
                                
                    class BOInstance {
                        static [string]$LogFolder = 'C:\temp\BO_Service_Management\'
                        static [string]$LogName = "$((Get-Date).ToShortDateString().replace('/','-'))_BO_Service_Management.txt"

                        [string]$ExeLocation
                        [string]$Username
                        [string]$Password
                        [string]$Authentication
                        [BOService[]]$Services
                        [string[]]$ExcludedServices = , 'CentralManagementServer'
                        [string]$LogLevel = 'Error'
                        [bool]$LogExternal = $true
                        [BOSpecialCaseRestart[]]$SpecialRestartCases
                    
                        BOInstance(
                            [string]$ExeLocation,
                            [string]$Username,
                            [string]$Password,
                            [string]$Authentication
                        ) {
                            [BOInstance]::CleanLogs()
                            $LogLoc = 'Constructor'
                            $this.LogDebug($LogLoc, 'Instanciated using 4 parameter constructor')
                            $this.LogDebug($LogLoc, "Parameter `"ExeLocation`" is `"$ExeLocation`"")
                            $this.LogDebug($LogLoc, "Parameter `"Username`" is `"$Username`"")
                            $this.LogDebug($LogLoc, "Parameter `"Password`" is not disclosed")
                            $this.LogDebug($LogLoc, "Parameter `"Authentication`" is `"$Authentication`"")
                            $this.ExeLocation = $ExeLocation
                            $this.Username = $Username
                            $this.Password = $Password
                            $this.Authentication = $Authentication
                            $this.CheckServer()
                            $this.LogInfo($LogLoc, 'Parameters validated successfully')
                            $this.UpdateServices()
                        }
                
                        BOInstance(
                            [string]$Password
                        ) {
                            [BOInstance]::CleanLogs()
                            $LogLoc = 'Constructor'
                            $this.LogDebug($LogLoc, 'Instanciated using 1 parameter constructor')
                            $this.LogDebug($LogLoc, "Parameter `"Password`" is not disclosed")
                            $this.ExeLocation = 'F:\BusinessObjects\SAP BusinessObjects Enterprise XI 4.0\win64_x64\ccm.exe'
                            $this.Username = 'appd_monitoring'
                            $this.Authentication = 'secEnterprise'
                            $this.Password = $Password
                            $this.CheckServer()
                            $this.LogInfo($LogLoc, 'Parameters validated successfully')
                            $this.UpdateServices()
                        }
                
                
                        [void]CheckServer() {
                            $LogLoc = 'CheckServer'
                            try {
                                $CorrectParams = (& $this.ExeLocation -Display -Username $this.Username -Password $this.Password -Authentication $this.Authentication)
                            }
                            catch {
                                $this.LogCritical($LogLoc, "Parameter `"ExeLocation`" is invalid. Terminating.")
                                throw "Parameter `"ExeLocation`" is incorrect or insuficcient permissions were used."
                            }
                            if ($CorrectParams[2].StartsWith('Unable')) {
                                $this.LogCritical($LogLoc, "$($CorrectParams[2]): $($CorrectParams[3])")
                                throw "$($CorrectParams[2]): $($CorrectParams[3])"
                            }
                        }
                
                        [BOService]StartService([BOService]$Service) {
                            $LogLoc = 'StartService'
                            $this.LogDebug($LogLoc, "Starting service `"$($Service.ServiceName)`" on host `"$($Service.ServerName)`" with status `"$($Service.Status)`" and state `"$($Service.State)`"")
                            
                            $this.SendRawCommand('-managedstart', $Service.CommandName)
                            $Service = $this.WaitServiceStart($Service)

                            return $Service
                        }
                
                        [BOService]StopService([BOService]$Service) {
                            $LogLoc = 'StopService'
                            $this.LogDebug($LogLoc, "Stopping service `"$($Service.ServiceName)`" on host `"$($Service.ServerName)`" with status `"$($Service.Status)`" and state `"$($Service.State)`"")
                            
                            $this.SendRawCommand('-managedstop', $Service.CommandName)
                            $Service = $this.UpdateServices($Service)
                            
                            $Attempts = 0
                            while ($Service.State -ne 'Stopped' -and $Attempts -lt 12) {
                                $this.LogError($LogLoc, "Service `"$($Service.ServiceName)`" has not entered stopped state after $($Attempts * 5) seconds")
                                Start-Sleep -Seconds 5
                                $Service = $this.UpdateServices($Service)
                                $Attempts++
                            }
                            
                            if ($Service.State -ne 'Stopped') {
                                $this.LogCritical($LogLoc, "Service `"$($Service.ServiceName)`" has not entered stopped state after $($Attempts * 5) seconds and will be forcefully terminated")
                                $Service = $this.TerminateService($Service)
                            }

                            return $Service
                        }
                
                        [BOService]EnableService([BOService]$Service) {
                            $LogLoc = 'EnableService'
                            $this.LogDebug($LogLoc, "Enabling service `"$($Service.ServiceName)`" on host `"$($Service.ServerName)`" with status `"$($Service.Status)`" and state `"$($Service.State)`"")
                            $this.SendRawCommand('-enable', $Service.CommandName)
                            return $this.UpdateServices($Service)	
                        }
                
                        [BOService]DisableService([BOService]$Service) {
                            $LogLoc = 'DisableService'
                            $this.LogDebug($LogLoc, "Disabling service `"$($Service.ServiceName)`" on host `"$($Service.ServerName)`" with status `"$($Service.Status)`" and state `"$($Service.State)`"")
                            $this.SendRawCommand('-disable', $Service.CommandName)
                            return $this.UpdateServices($Service)
                        }
                
                        [BOService]TerminateService([BOService]$Service) {
                            $LogLoc = 'TerminateService'
                            $this.LogDebug($LogLoc, "Terminating service `"$($Service.ServiceName)`" on host `"$($Service.ServerName)`" with status `"$($Service.Status)`" and state `"$($Service.State)`"")
                            $this.SendRawCommand('-managedforceterminate', $Service.CommandName)
                            return $this.UpdateServices($Service)
                        }

                        [void]WaitServicesStart() {
                            $LogLoc = 'WaitServicesStart'
                            $this.LogInfo($LogLoc, 'Waiting for services to start')
                            $this.UpdateServices()
                            
                            $Attempts = 0
                            while (($this.Services | Where-Object { $_.State -eq 'Starting' -or $_.State -eq 'Initializing' }).Count -gt 0 -and $Attempts -lt 24) {
                                $Attempts++
                                $this.LogInfo($LogLoc, "Waiting for $(($this.Services | Where-Object { $_.State -eq 'Starting' -or $_.State -eq 'Initializing' }).Count) services to start")
                                
                                Start-Sleep -Seconds 5
                                $this.LogInfo($LogLoc, "Waited $($Attempts * 5) seconds for services to start")
                                $this.UpdateServices()
                            }
                        }

                        [BOService]WaitServiceStart([BOService]$Service) {
                            $LogLoc = 'WaitServiceStart'
                            $this.LogInfo($LogLoc, "Waiting for service `"$($Service.CommandName)`" to start")
                            
                            $Attempts = 0
                            while (($Service.State -eq 'Starting' -or $Service.State -eq 'Initializing') -and $Attempts -lt 24) {
                                $Attempts++
                                
                                Start-Sleep -Seconds 5
                                $this.LogInfo($LogLoc, "Waited $($Attempts * 5) seconds for service `"$($Service.CommandName)`" to start")
                                $Service = $this.UpdateServices($Service)
                            }
                            return $Service
                        }

                        [void]RestartService([BOService]$Service) {
                            $LogLoc = 'RestartService'
                            $this.LogInfo($LogLoc, "Beginning restart of service `"$($Service.CommandName)`"")

                            if ($Service.ServiceName -in $this.SpecialRestartCases.ServiceName) {
                                $this.LogInfo($LogLoc, "Special restart case possible for service `"$($Service.CommandName)`"")
                                $SpecialService = $this.SpecialRestart($Service)

                                if ($null -eq $SpecialService) {
                                    $this.LogInfo($LogLoc, "Special restart case not met for service `"$($Service.CommandName).`" Continuing typical restart")
                                }
                                else {
                                    $this.LogInfo($LogLoc, "Special restart case finished for service `"$($Service.CommandName).`" Ending restart of service")
                                    return
                                }

                            }

                            if ($Service.Status -ne 'Disabled') {
                                $Service = $this.DisableService($Service)
                            }

                            switch ($Service.State) {
                                { 'Running', 'Starting', 'Running With Errors' -contains $_ } {
                                    $Service = $this.StopService($Service)
                                }

                                'Stopped' {
                                    break
                                }
                            }

                            $Service = $this.StartService($Service)

                            $Service = $this.EnableService($Service)
                            
                            $this.LogInfo($LogLoc, "End of restart of service $($Service.CommandName)")
                            $this.LogDebug($LogLoc, "Status was `"$($Service.Status)`" and state was `"$($Service.State)`"")
                        }

                        [BOService]SpecialRestart([BOService]$Service) {
                            $LogLoc = 'SpecialRestart'
                            $this.LogInfo($LogLoc, "Attempting to perform a special restart of service `"$($Service.ServiceName)`"")
                            $BOSpecialCases = $this.SpecialRestartCases | Where-Object { $_.ServiceName -eq $Service.ServiceName }
                            $TrueCases = ($BOSpecialCases | Where-Object { (Invoke-Expression $_.SpecialCase) -eq $true })

                            if ($null -eq $TrueCases) {
                                $this.LogInfo($LogLoc, 'No special cases were met. Returning for normal restart')
                                return $null
                            }
                            else {
                                $TrueCase = $TrueCases[0]
                            }

                            foreach ($Instruction in $TrueCase.Instructions) {
                                $InstructionService = $this.Services | Where-Object { $_.ServiceName -eq $Instruction.ServiceName -and $_.ServerName -eq $Service.ServerName }
                                $ServiceString = "[BOService]::new('$($InstructionService.ServerName)','$($InstructionService.ServiceName)','$($InstructionService.State)','$($InstructionService.Status)',$(if ($InstructionService.ProcessId -eq '') {'$null'} else {$InstructionService.ProcessId}))"
                                $this.LogDebug($LogLoc, "Starting $($Instruction.ServiceInstruction) command on $($Instruction.CommandName)")
                                $FullCommand = "`$this.$($Instruction.ServiceInstruction)Service($ServiceString)"
                                $this.LogDebug($LogLoc, "Full command to be invoked `"$FullCommand`"")
                                Invoke-Expression $FullCommand
                            }

                            $Service = $this.UpdateServices($Service)

                            return $Service
                        }
                
                        [void]RestartServices([object[]]$CommandNames) {
                            $LogLoc = 'RestartServices'
                            $this.LogInfo($LogLoc, "Attempting to restart the following services: $($CommandNames -Join ', ')")
                            foreach ($CommandName in $CommandNames) {
                                [BOService]$Service = $this.Services | Where-Object { $_.CommandName -eq $CommandName }
                                if ($Service.State -ne 'Running' -or $Service.Status -ne 'Enabled') {
                                    $this.RestartService($Service)
                                }
                            }
                        }
                
                        [void]RestartAllServices() {
                            $LogLoc = 'RestartAllServices'
                            $this.LogInfo($LogLoc, 'Triggering a restart of all services')
                            $this.RestartServices($this.Services.CommandName)
                        }
                
                        [void]RestartServices([string]$ComputerName) {
                            $LogLoc = 'RestartServices'
                            $this.LogDebug($LogLoc, "Triggering a restart of all services on host `"$ComputerName`"")
                            $this.RestartServices(($this.Services | Where-Object { $_.ServerName -eq $ComputerName }).CommandName)
                        }
                
                        [BOService]UpdateServices([BOService]$Service) {
                            $LogLoc = 'UpdateServices'
                            $this.LogDebug($LogLoc, "Triggering an update of services to refresh service `"$($Service.CommandName)`"")
                            $CommandName = $Service.CommandName
                            $this.UpdateServices()
                            return $this.Services | Where-Object { $_.CommandName -like $CommandName }
                        }
                
                        [void]UpdateServices() {
                            $LogLoc = 'UpdateServices'
                            $this.LogDebug($LogLoc, 'Updating services')
                            [string[]]$RawServices = $this.GetRawDetails()
                            [BOService[]]$this.Services = $null
                            foreach ($i in 0..($RawServices.Count - 1)) {
                                if ($RawServices[$i].StartsWith('Server Name:')) {
                                    $this.LogDebug($LogLoc, 'Service found in raw text')
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
                                    if ($state.Equals('Running')) {
                                        $ProcessId = $RawServices[$i + 4].Split(':', 2)[1].Trim()
                                    }
                                    $this.LogDebug($LogLoc, "PID is `"$ProcessId`"")
                                    $NewService = [BOService]::new($ServerName, $ServiceName, $State, $Status, $ProcessId)
                                    $this.Services += $NewService
                                }
                            }
                            $this.LogDebug($LogLoc, 'Update finished')
                        }
                
                        [BOService[]]ValidateServices() {
                            $LogLoc = 'ValidateServices'
                            $this.LogDebug($LogLoc, 'Started validating services')
                            $this.UpdateServices()
                            $this.LogDebug($LogLoc, 'Finished validating services')
                            return $this.Services | Where-Object { $_.State -ne 'Running' -or $_.Status -ne 'Enabled' }
                        }
                
                        [string[]]GetRawDetails() {
                            return $this.SendRawCommand('-Display')
                        }
                
                        [object]SendRawCommand([string]$Command, [string]$Data) {
                            $LogLoc = 'SendRawCommand'
                            $FullCommand = "$($this.ExeLocation) $Command $Data -Username $($this.Username) -Password CONFIDENTIAL -Authentication $($this.Authentication)"
                            $this.LogDebug($LogLoc, "Running command: $FullCommand")
                            return & $this.ExeLocation $Command $Data -Username $this.Username -Password $this.Password -Authentication $this.Authentication
                        }
                
                        [object]SendRawCommand([string]$Command) {
                            return $this.SendRawCommand($Command, $null)
                        }
                
                        [void]Log([string]$From, [string]$Level, [string]$Message) {
                            if (!$(Test-Path $([BOInstance]::LogFolder))) {
                                New-Item -Path $([BOInstance]::LogFolder) -ItemType Directory
                            }
                            $ToLog = "[$(Get-Date)][$From][$level] $Message"
                            $ToLog | Add-Content "$([BOInstance]::LogFolder)$([BOInstance]::LogName)"
                            if ($this.LogExternal) {
                                Write-Host $ToLog
                            }
                        }
                
                        [void]LogCritical([string]$From, [string]$Message) {
                            if ([int][LogLevels]$this.LogLevel -ge [int][LogLevels]'Critical') {
                                $this.Log($From, 'Critical', $Message)
                            }
                        }
                
                        [void]LogError([string]$From, [string]$Message) {
                            if ([int][LogLevels]$this.LogLevel -ge [int][LogLevels]'Error') {
                                $this.Log($From, 'Error', $Message)
                            }
                        }
                
                        [void]LogInfo([string]$From, [string]$Message) {
                            if ([int][LogLevels]$this.LogLevel -ge [int][LogLevels]'Info') {
                                $this.Log($From, 'Info', $Message)
                            }
                        }
                
                        [void]LogDebug([string]$From, [string]$Message) {
                            if ([int][LogLevels]$this.LogLevel -ge [int][LogLevels]'Debug') {
                                $this.Log($From, 'Debug', $Message)
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

                    function Start-BOServices {
                        param (
                            [string[]]$Services
                        )
                
                        $BOServices = 'Apache Tomcat for BI 4', "Server Intelligence Agent ($env:COMPUTERNAME )"
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
                        return Get-Service 'Apache Tomcat for BI 4', "Server Intelligence Agent ($env:computername)" | Select-Object DisplayName, Status
                    }
                    # End supporting classes and functions

                    # Get and make sure the BO windows services are running
                    $Attempts = 0
                    $WinServices = Get-BOServices
                    Write-Host "[$(Get-Date)] Starting Windows services on server $Computer"
                    while ($Attempts -lt 8 -and ($WinServices | Where-Object { $_.Status -ne 'Running' }).Count -gt 0) {
                        # Only attempt to start services that aren't running or will start
                        foreach ($WinService in ($WinServices | Where-Object { $_.Status -notin 'Running', 'StartPending' })) {
                            Start-BOServices -Services $WinService.DisplayName
                        }

                        # If service has start pending, wait for it
                        $WinServices = Get-BOServices
                        if (($WinServices | Where-Object { $_.Status -eq 'StartPending' }).Count -gt 0) { 
                            Start-Sleep -Seconds ($Attempts * 5)
                        }

                        $WinServices = Get-BOServices
                        $Attempts++
                        Write-Host "[$(Get-Date)] Failed attempts to start Windows services on server $($Computer): $Attempts"
                    }

                    # Determine if any services aren't running
                    $BadServices = $WinServices | Where-Object { $_.Status -ne 'Running' }
                    if ($BadServices.Count -gt 0) {
                        Write-Host "[$(Get-Date)] One or more Windows services on failed to start on server $($Computer): $($BadServices.DisplayName -join ', ')"
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
                            if ($_ -like 'Unable to logon to CMS: Reason: Unable to log on: Could not connect to server*') {
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

                    # Creates a log on the server which stores information about the BO service process. See the BOInstance class to see whats logged and where
                    $BOServer.LogLevel = 'Info'
                    $BOServer.SpecialRestartCases += [BOSpecialCaseRestart]::new(
                        'CrystalReportsCacheServer',
                        '$Service.State -eq "Running with Errors"',
                        @(
                            [BORestartInstruction]::new('AdaptiveJobServer', 'Disable'),
                            [BORestartInstruction]::new('AdaptiveJobServer', 'Stop'),
                            [BORestartInstruction]::new('CrystalReportsCacheServer', 'Disable'),
                            [BORestartInstruction]::new('CrystalReportsCacheServer', 'Stop'),
                            [BORestartInstruction]::new('CrystalReports2016ProcessingServer', 'Disable'),
                            [BORestartInstruction]::new('CrystalReports2016ProcessingServer', 'Stop'),
                            [BORestartInstruction]::new('CrystalReportsProcessingServer', 'Disable'),
                            [BORestartInstruction]::new('CrystalReportsProcessingServer', 'Stop'),
                            [BORestartInstruction]::new('CrystalReportsCacheServer', 'Start'),
                            [BORestartInstruction]::new('CrystalReportsCacheServer', 'Enable'),
                            [BORestartInstruction]::new('CrystalReports2016ProcessingServer', 'Start'),
                            [BORestartInstruction]::new('CrystalReportsProcessingServer', 'Start'),
                            [BORestartInstruction]::new('CrystalReports2016ProcessingServer', 'Enable'),
                            [BORestartInstruction]::new('CrystalReportsProcessingServer', 'Enable'),
                            [BORestartInstruction]::new('AdaptiveJobServer', 'Start'),
                            [BORestartInstruction]::new('AdaptiveJobServer', 'Enable')
                        )
                    )

                    # Waits until all services are started or 2 minutes, whichever comes first
                    $BOServer.WaitServicesStart()

                    # Restart BO services that aren't running or enabled
                    $Attempts = 0
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

            Write-Host "[$(Get-Date)] Starting AppD monitoring agent"
            Invoke-Command -Session $Session -ScriptBlock {
                Start-Service 'Appdynamics Machine Agent'
            }

            Write-Host "[$(Get-Date)] Terminating PSSession to server $Computer" 
            Remove-PSSession $Session

            if ($NumRestarts -eq 3) {
                $FailedRestarts += , $Computer
            }
            $NumRestarts++
        }
    }

    # Report back status at end of process
    if ($FailedRestarts.Count -gt 0) {
        Write-Host "[$(Get-Date)] The following servers failed to restart: $($FailedRestarts -join ', ')"
    }
    else {
        Write-Host "[$(Get-Date)] All specified server restarted sucessfully"
    }

    foreach ($Computer in $Computers) {
        Set-Item WSMan:\\localhost\client\TrustedHosts -Value $(((Get-Item WSMan:\\localhost\client\TrustedHosts).Value.Split(',') | Where-Object { $_ -ne $Computer }) -join ',') -Force
    }
        
}
catch {
    $detailedError = $_
    Write-Host "##vso[task.logissue type=error]$detailedError"
    Write-Host "##vso[task.complete result=Failed;]Script execution failed: $detailedError"
}