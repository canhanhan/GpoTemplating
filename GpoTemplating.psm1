function Migrate-Text {
	[CmdletBinding()]
	param (		
        [AllowEmptyString()]
        [Parameter(Mandatory=$true)]
        [string]$Content,		

        [ValidateNotNull()]
        [Parameter(Mandatory=$true)]
		[Hashtable]$Variables
	)
	
    Begin { Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started" } 
    Process {
        if ($Content -eq $null) { return $null }
	    $temp = "";
	    $output = $content;
	    while ($temp -ne $output) { 
		    $temp = $output
		    $output = [regex]::Replace($output, '\{\{(?<key>\w+)\}\}', { 	
			    param($match); 
			
			    $key = $match.Groups['key'].Value
			    if (!$variables.ContainsKey($key)) {
				    Write-Error "Cannot resolve template variable $key"
			    }
			
			    $variables[$key] 
		    })		
	    }
	
	    $output 
    }
    End { Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"} 
}

function Migrate-Registry {
    [CmdletBinding(SupportsShouldProcess=$true)]
	param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Path,


        [ValidateNotNull()]
        [Parameter(Mandatory=$true)]
		[Hashtable]$Variables
	)

    Begin { Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started" } 
	
    Process {
        if (!(Test-Path $path)) { return; }

        if ($pscmdlet.ShouldProcess($path)) {	
	        $parser = New-Object GroupPolicy.Parser.RegistryFile
	        $parser.Open($path)
	        $parser.Settings | ForEach-Object { 
		        $_.Value = Migrate-Text -Variables $variables -Content $_.Value
		
		        if ($_.Type -eq "REG_SZ" -or $_.Type -eq "REG_EXPAND_SZ") {
			        $_.Data = Migrate-Text -Variables $variables -Content $_.Data
		        } elseif ($_.Type -eq "REG_MULTI_SZ") {
			        $_.Data = ($_.Data | ForEach-Object { Migrate-Text -Variables $variables -Content $_ } )
		        }				
	        }

	        $parser.Save()
        }
    }

    End { Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"} 
}

function Migrate-File {
    [CmdletBinding(SupportsShouldProcess=$true)]
	param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]  
		[Text.Encoding]$Encoding,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]        
		$Folder,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
        [string]
		$File,

        [ValidateNotNull()]
        [Parameter(Mandatory=$true)]
		[Hashtable]$Variables        
	)

    Begin { Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started" } 
	
    Process {
	    $path = Join-Path $folder $file
        if (!(Test-Path $path)) { return; }

        if ($pscmdlet.ShouldProcess($path)) {	
	        $fileInfo = New-Object System.IO.FileInfo($path)
	        $wasReadOnly = $false;
	
	        if ($fileInfo.IsReadOnly)
	        {
		        $wasReadOnly = $true;
		        $fileInfo.IsReadOnly = $false;
	        }
	
	        $content = Migrate-Text -Variables $variables -Content ([IO.File]::ReadAllText($path, $encoding))
						
	        if ($_GPO_CUSTOM_ACTIONS.ContainsKey($file)) { 
               @($_GPO_CUSTOM_ACTIONS[$file]) | ForEach-Object { $content = ($content | &$_)  }
            }
						
			[IO.File]::WriteAllText($path, $content, $encoding)

	        if ($wasReadOnly) { $fileInfo.IsReadOnly = $true; }	
        }
    }
    End { Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended" } 
}

function Get-GroupSID {
    [CmdletBinding()]
	param(
        [ValidateNotNullOrEmpty()]     
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Group
    )

    Begin { Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started" } 

    Process {
	    if ($group.Contains("\")) {
		    $domainName = $group.Substring(0, $group.IndexOf("\"))
		    $groupName = $group.Substring($group.IndexOf("\") + 1)
	    } elseif ($group.Contains("@")) {
		    $groupName = $group.Substring(0, $group.IndexOf("@"))
		    $domainName = $group.Substring($group.IndexOf("@") + 1)			
	    } else {
		    return
	    }
	
	    $domain = Get-ADDomain $domainName -ErrorAction Stop
	    $groups = @(Get-AdObject -SearchBase $domain.DistinguishedName -Property SamAccountName, ObjectSid  -Filter  { DisplayName -eq $groupName -or Name -eq $groupName -or cn -eq $groupName -or SamAccountName -eq $groupName } -Server (Get-ADDomainController -Discover -DomainName $domain.Name -ErrorAction Stop).IPv4Address -ErrorAction Stop)
	
	    if ($groups.Length -eq 0) {
		    Write-Warning "Cannot resolve $groupName in $domainName"
	    } elseif ($groups.Length -gt 1) {
		    Write-Error "There are multiple results for $groupName in $domainName. The search is done by DisplayName, Name, CN, SamAccountName attributes."
	    } else {
		    $groups | Select-Object -First 1 -Property @{Name="Name";Expr={"$($domain.NetbiosName)\$($_.SamAccountName)"}}, @{Name="SID";Expr={$_.ObjectSid}}
	    }
    }
    End { Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended" } 
}

function Set-GroupSID {
    [CmdletBinding()]
	param (
        [ValidateNotNull()]     
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[Xml.XmlNode] $Group,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
		[string]$NameAttribute,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true)]
		[string]$SidAttribute,
		
        [ValidateNotNull()]
        [Parameter(Mandatory=$true)]
		[Hashtable]$Variables     
	)

    Begin { Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started" } 
	
    Process {
	    if ($group.Attributes[$nameAttribute] -ne $null) {
		    $groupName = $group.Attributes[$nameAttribute].Value
	    }
	
	    if ([string]::IsNullOrEmpty($groupName)) { return $null }
	
	    $groupName = Migrate-Text -Variables $variables -Content $groupName
		
	    try  {
		    $info = Get-GroupSID $groupName
		    if ($info -eq $null) { return $null }
		
		    $group.Attributes[$nameAttribute].Value = $info.Name
		    $group.Attributes[$sidAttribute].Value = $info.SID
	    } catch {
		    Write-Warning "Cannot resolve group $groupName to SID. Error: $($Error[0])"
            return $null
	    }
    }

    End { Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended" } 
}

function Migrate-PreferenceFile {
    [CmdletBinding(SupportsShouldProcess=$true)]
	param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Path,


        [ValidateNotNull()]
        [Parameter(Mandatory=$true)]
		[Hashtable]$Variables
	)
	
    if (!(Test-Path $path)) { return }

    if ($pscmdlet.ShouldProcess($path)) {	 
	    $document = [xml] (Get-Content -Path $path)
	    $document.GetElementsByTagName("FilterGroup") | Set-GroupSID -NameAttribute "name" -SIDAttribute "sid" -Variables $variables
	    $document.GetElementsByTagName("Group") | Set-GroupSID -NameAttribute "groupName" -SIDAttribute "groupSid" -Variables $variables
	    $document.GetElementsByTagName("Member") | Set-GroupSID -NameAttribute "name" -SIDAttribute "sid" -Variables $variables
	
	    $document.InnerXml = Migrate-Text -Variables $variables -Content $document.InnerXml
	
	    $document.Save($path)
    }
}

function Migrate-Preferences {
    [CmdletBinding(SupportsShouldProcess=$true)]
	param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Path,


        [ValidateNotNull()]
        [Parameter(Mandatory=$true)]
		[Hashtable]$Variables
	)
	
	if (!(Test-Path $path)) { return }
	    
	Get-ChildItem -Path $path -Directory | ForEach-Object { Migrate-Preferences -Path $_.FullName -Variables $variables }
	Get-ChildItem -Path $path -File | Where-Object { $_.Extension -eq ".xml" } | ForEach-Object { Migrate-PreferenceFile -Path $_.FullName -Variables $variables }
}

function Migrate-GPO {
	[CmdletBinding(SupportsShouldProcess=$true)]
	param (
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Path,

		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Hashtable]	
		$Variables
	)
	
    $gpoPath = Join-Path $Path $_GPO_PATH
    if (!(Test-Path $gpoPath)) { throw "Path $gpoPath does not exist" }

	Migrate-Preferences -Path (Join-Path (Join-Path $gpoPath $_GPO_PATH_MACHINE) $_GPO_PATH_PREFERENCES) -Variables $variables
	Migrate-Preferences -Path (Join-Path (Join-Path $gpoPath $_GPO_PATH_USER) $_GPO_PATH_PREFERENCES) -Variables $variables
	Migrate-Registry -Path (Join-Path (Join-Path $gpoPath $_GPO_PATH_MACHINE) $_GPO_REGISTRY_FILE) -Variables $variables
	Migrate-Registry -Path (Join-Path (Join-Path $gpoPath $_GPO_PATH_USER) $_GPO_REGISTRY_FILE) -Variables $variables
	
	$_GPO_FILES.Keys | ForEach-Object {
		$encoding = New-Object "System.Text.$($_)Encoding"
		$_GPO_FILES[$_] | ForEach-Object { 	
			$file = $_
			($_GPO_PATH_MACHINE, $_GPO_PATH_USER) | ForEach-Object {
				$folder = $_
				Get-ChildItem -Path "$gpoPath\\$folder\\$file" -Recurse -File -ErrorAction SilentlyContinue | Select-Object Name, @{Name="Path";Expr={[IO.Path]::GetDirectoryName($_)}} | ForEach-Object {
					Migrate-File -Encoding $encoding -Folder $_.Path -File $_.Name -Variables $variables
				}
			}			
		}
	}	
}

function Copy-GPOEx {
	[CmdletBinding(SupportsShouldProcess=$true)]
	param (
		[parameter(Mandatory=$true, HelpMessage="Source policy name")]
		[ValidateNotNullOrEmpty()]
		[string]
		$SourcePolicy,		
	
		[parameter(Mandatory=$false, HelpMessage="Source domain name or FQDN. (Default: Current domain)")]
		[ValidateNotNullOrEmpty()]
		[string]
		$SourceDomain=$env:USERDNSDOMAIN,
		
		[parameter(Mandatory=$false, HelpMessage="A domain controller in source domain. (Default: Any domain controller in domain)")]
		[ValidateNotNullOrEmpty()]
		[string]		
		$SourceServer=$sourceDomain,

		[parameter(Mandatory=$false, HelpMessage="Credentials to connect the source domain (Default: none)")]
		[ValidateNotNull()]
		[PSCredential]	
		$SourceCredential,
	
		[parameter(Mandatory=$false, HelpMessage="Target policy name (Default: Source policy name)")]
		[ValidateNotNullOrEmpty()]
		[string]			
		$TargetPolicy=$sourcePolicy,		
		
		[parameter(Mandatory=$false, HelpMessage="Target domain name or FQDN. (Default: Source domain)")]
		[ValidateNotNullOrEmpty()]
		[string]			
		$TargetDomain=$sourceDomain,
		
		[parameter(Mandatory=$false, HelpMessage="A domain controller in target domain. (Default: Any domain controller in domain)")]
		[ValidateNotNullOrEmpty()]
		[string]			
		$TargetServer=$targetDomain,
		
		[parameter(Mandatory=$false, HelpMessage="Credentials to connect the target domain (Default: none)")]
		[ValidateNotNull()]
		[PSCredential]			
		$TargetCredential,
		
		[parameter(Mandatory=$false, HelpMessage="Path to store GPO backups (Default: C:\Temp)")]
		[ValidateNotNullOrEmpty()]
		[string]			
		$BackupPath="C:\Temp",
		
		[parameter(Mandatory=$false, HelpMessage="Path to the configuration file (Default: none)")]
		[ValidateNotNullOrEmpty()]
		[string]			
		$ConfigFile
	)
	
	$operation = { 
		param($sourcePolicy, $backupPath, $sourceDomain, $sourceServer); 
		Import-Module GroupPolicy; 
		Write-Host "Backing up $sourcePolicy" 
		Backup-GPO -Name $sourcePolicy -Path $backupPath -Domain $sourceDomain -Server $sourceServer -ErrorAction Stop 
	}	
	if ($sourceCredential -ne $null) 
	{
		$backup = Invoke-Command -ComputerName $Env:COMPUTERNAME -ScriptBlock $operation -Credential $sourceCredential -Authentication CredSSP -ArgumentList $sourcePolicy, $backupPath, $sourceDomain, $sourceServer  -ErrorAction Stop
	} else {
		$backup = &$operation $sourcePolicy $backupPath $sourceDomain $sourceServer;
	}
	
	$gpoPath = Join-Path $backup.BackupDirectory $backup.Id.ToString("B");		
	if (![string]::IsNullOrEmpty($configFile)) {	
		Write-Host "Migrating the policy $gpoPath" 
		$variables = ((Get-Content $configFile -ErrorAction Stop)  -join "`n" -replace "\\", "\\" | ConvertFrom-StringData)
		Migrate-GPO -Path $gpoPath -Variables $variables -ErrorAction Stop
	}
	
	
	$operation = { param($backup, $targetPolicy, $targetDomain, $targetServer); 
		Import-Module GroupPolicy;  
		Write-Host "Restoring $targetPolicy"
		Import-GPO -BackupId $backup.Id.ToString("B") -TargetName $targetPolicy -Domain $targetDomain -CreateIfNeeded -Path $backup.BackupDirectory -Server $targetServer -ErrorAction Stop 
	}
	if ($targetCredential -ne $null) 
	{
		Invoke-Command -ComputerName $Env:COMPUTERNAME -ScriptBlock $operation -Credential $targetCredential -Authentication CredSSP -ArgumentList $backup, $targetPolicy, $targetDomain, $targetServer -ErrorAction Stop 
	} else {
		&$operation $backup $targetPolicy $targetDomain $targetServer;
	}		
}

$_GPO_FILES = @{
	"Unicode"= @("Microsoft\IEAK\branding\ratings\ratings.inf",
				 "Microsoft\IEAK\branding\ratings\ratrsop.inf",
				 "Microsoft\IEAK\branding\authcode\authcode.inf",
				 "Microsoft\IEAK\branding\programs\programs.inf",
				 "scripts\scripts.ini",
				 "scripts\psscripts.ini",
				 "Documents & Settings\fdeploy.ini",
				 "Documents & Settings\fdeploy1.ini",
                 "Microsoft\Windows NT\SecEdit\GptTmpl.inf",
				 "*.aas"
			 );
	"UTF8" = @("Microsoft\Windows NT\Audit\Audit.csv",
			   "Microsoft\Windows NT\CAP\CAP.inf"
			 );
	"ascii"= @("Microsoft\IEAK\branding\zones\seczrsop.inf",
			   "Microsoft\IEAK\branding\zones\seczones.inf",	
			   "Microsoft\IEAK\install.ins"
			 )		 
}

$_GPO_CUSTOM_ACTIONS = @{
	"Microsoft\Windows NT\SecEdit\GptTmpl.inf"={
        param(
            [ValidateNotNull()]
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$Content
        ) 
    
        Begin { Write-Verbose "Translate-SecEditSIDs Function started" } 

        Process 
        {
            $lines = $content -split "`r`n"
            $start = $lines.IndexOf("[Group Membership]")
            if ($start -eq -1) { return $content; }
            $end = $lines[($start+1)..($lines.Length)].IndexOf((@($lines[($start+1)..($lines.Length)] -match "^\[.+") | Select-Object -First 1))
            if ($end -eq -1) { $end = $lines.Length } else { $end += $start }

            $newLines = $lines[($start)..$end] | ForEach-Object {
                if ([string]::IsNullOrWhiteSpace($_) -or $_.StartsWith("[")) { return $_; }

                $memberSeperator = $_.IndexOf("__Member")
                if ($memberSeperator -eq -1) { return $_; }
                $sourceGroup = $_.Substring(0, $memberSeperator);
                $isSourceResolved = $sourceGroup.StartsWith("*")
                $equalsPosition = $_.IndexOf("=")
                $type = $_.Substring($memberSeperator, $equalsPosition - $memberSeperator)
                $targetGroups = $_.Substring($equalsPosition + 1).Trim() -split "," | ForEach-Object {
                    if ($_.StartsWith("*") -or [string]::IsNullOrWhiteSpace($_)) { return $_ }
                    $groupSid = Get-GroupSID $_
                    if ($groupSid -ne $null) {
                        "*$($groupSid.SID)"
                    } else {
                        $_
                    }
                }

                if (!$isSourceResolved) {
                    $sourceSid = Get-GroupSID $sourceGroup
                    if ($sourceSid -ne $null) {
                        $sourceGroup = "*$($sourceSid.SID)"
                    } 
                }

                "$($sourceGroup + $type)= $($targetGroups -join ',')"
            }

            for($i=0; $i -lt $newLines.Length; $i++) {
                $lines[$start+$i] = $newLines[$i]
            }

            return $lines -join "`n"
        }

        End { Write-Verbose "Translate-SecEditSIDs Function ended"} 
    }
}

$_GPO_PATH = "DomainSysvol\GPO"
$_GPO_PATH_PREFERENCES = "Preferences";
$_GPO_PATH_USER = "User";
$_GPO_PATH_MACHINE = "Machine";
$_GPO_REGISTRY_FILE = "registry.pol";