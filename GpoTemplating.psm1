function Migrate-GPO {
	[CmdletBinding(SupportsShouldProcess=$true)]
	param (
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$gpoPath,

		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Hashtable]	
		$variables
	)
	
	if ($pscmdlet.ShouldProcess($gpoPath)) {
		$migrator = New-Object -TypeName "GroupPolicy.Migration.Migrator" -ErrorAction Stop
		$migrator.Migrate($gpoPath, $variables);	
	}
}

function Copy-GPOEx {
	[CmdletBinding(SupportsShouldProcess=$true)]
	param (
		[parameter(Mandatory=$true, HelpMessage="Source policy name")]
		[ValidateNotNullOrEmpty()]
		[string]
		$sourcePolicy,		
	
		[parameter(Mandatory=$false, HelpMessage="Source domain name or FQDN. (Default: Current domain)")]
		[ValidateNotNullOrEmpty()]
		[string]
		$sourceDomain=$env:USERDNSDOMAIN,
		
		[parameter(Mandatory=$false, HelpMessage="A domain controller in source domain. (Default: Any domain controller in domain)")]
		[ValidateNotNullOrEmpty()]
		[string]		
		$sourceServer=$sourceDomain,

		[parameter(Mandatory=$false, HelpMessage="Credentials to connect the source domain (Default: none)")]
		[ValidateNotNull()]
		[PSCredential]	
		$sourceCredential,
	
		[parameter(Mandatory=$false, HelpMessage="Target policy name (Default: Source policy name)")]
		[ValidateNotNullOrEmpty()]
		[string]			
		$targetPolicy=$sourcePolicy,		
		
		[parameter(Mandatory=$false, HelpMessage="Target domain name or FQDN. (Default: Source domain)")]
		[ValidateNotNullOrEmpty()]
		[string]			
		$targetDomain=$sourceDomain,
		
		[parameter(Mandatory=$false, HelpMessage="A domain controller in target domain. (Default: Any domain controller in domain)")]
		[ValidateNotNullOrEmpty()]
		[string]			
		$targetServer=$targetDomain,
		
		[parameter(Mandatory=$false, HelpMessage="Credentials to connect the target domain (Default: none)")]
		[ValidateNotNull()]
		[PSCredential]			
		$targetCredential,
		
		[parameter(Mandatory=$false, HelpMessage="Path to store GPO backups (Default: C:\Temp)")]
		[ValidateNotNullOrEmpty()]
		[string]			
		$backupPath="C:\Temp",
		
		[parameter(Mandatory=$false, HelpMessage="Path to the configuration file (Default: none)")]
		[ValidateNotNullOrEmpty()]
		[string]			
		$configFile
	)
	
	$operation = { param($sourcePolicy, $backupPath, $sourceDomain, $sourceServer); Import-Module GroupPolicy; Backup-GPO -Name $sourcePolicy -Path $backupPath -Domain $sourceDomain -Server $sourceServer -ErrorAction Stop }	
	if ($sourceCredential -ne $null) 
	{
		$backup = Invoke-Command -ComputerName $Env:COMPUTERNAME -ScriptBlock $operation -Credential $sourceCredential -Authentication CredSSP -ArgumentList $sourcePolicy, $backupPath, $sourceDomain, $sourceServer  -ErrorAction Stop
	} else {
		$backup = &$operation $sourcePolicy $backupPath $sourceDomain $sourceServer;
	}
	
	$gpoPath = Join-Path $backup.BackupDirectory $backup.Id.ToString("B");		
	if (![string]::IsNullOrEmpty($configFile)) {	
		$variables = ((Get-Content $configFile -ErrorAction Stop)  -join "`n" -replace "\\", "\\" | ConvertFrom-StringData)
		Migrate-GPO -GpoPath $gpoPath -Variables $variables -ErrorAction Stop
	}
	
	$operation = { param($backup, $targetPolicy, $targetDomain, $targetServer); Import-Module GroupPolicy;  Import-GPO -BackupId $backup.Id.ToString("B") -TargetName $targetPolicy -Domain $targetDomain -CreateIfNeeded -Path $backup.BackupDirectory -Server $targetServer -ErrorAction Stop }
	if ($targetCredential -ne $null) 
	{
		Invoke-Command -ComputerName $Env:COMPUTERNAME -ScriptBlock $operation -Credential $targetCredential -Authentication CredSSP -ArgumentList $backup, $targetPolicy, $targetDomain, $targetServer -ErrorAction Stop 
	} else {
		&$operation $backup $targetPolicy $targetDomain $targetServer;
	}		
}
