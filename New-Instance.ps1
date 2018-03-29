#Requires -Version 5
#Requires -RunAsAdministrator

using namespace System

[CmdletBinding(PositionalBinding = $false)]
param (
    [Parameter()]
    [string] $UserName,
    [Parameter()]
    [string] $AccessKey,
    [Parameter()]
    [string] $SecretAccessKey,
    [Parameter()]
    [string] $Region
)
BEGIN
{
    $Script:ErrorActionPreference = [Management.Automation.ActionPreference]::Stop
    Set-StrictMode -Version 1

    if ([string]::IsNullOrWhiteSpace($UserName))
    {
        throw [ArgumentException]::new("AWS account username must be specified.", 'UserName')
    }
    if ([string]::IsNullOrWhiteSpace($AccessKey))
    {
        throw [ArgumentException]::new("The access key must be specified.", 'AccessKey')
    }
    if ([string]::IsNullOrWhiteSpace($SecretAccessKey))
    {
        throw [ArgumentException]::new("The secret access key must be specified.", 'SecretAccessKey')
    }
    if ([string]::IsNullOrWhiteSpace($Region))
    {
        throw [ArgumentException]::new("The target AWS region must be specified.", 'Region')
    }
    
    if (-not (Get-Module -Listavailable -Name AWSPowerShell))
    {
        Install-Module -Name AWSPowerShell -Force
    }
    Import-Module AWSPowerShell

    Initialize-AWSDefaultConfiguration -AccessKey $AccessKey -SecretKey $SecretAccessKey -Region $Region

    Set-Item WSMan:\localhost\Client\TrustedHosts "*" -Force

    [string] $instanceType = 't2.micro'
    [string] $securityGroup = 'mySecGroup'
    [string] $keyName = 'myKey'

    function New-SecurityGroup
    {
        [CmdletBinding(PositionalBinding = $false)]
        param (
            [Parameter(Mandatory = $false)]
            [string] $SecurityGroupName
        )

        if ([string]::IsNullOrWhiteSpace($SecurityGroupName))
        {
            throw [ArgumentException]::new("The name of the security group must be specified.", 'SecurityGroupName')
        }

        if (Get-EC2SecurityGroup -GroupName $SecurityGroupName | ? { $_.GroupName -eq $SecurityGroupName })
        {
        
            Write-Host "Security group ""$SecurityGroupName"" exists, skipping."
            return
        }

        [string] $myIpRange = '0.0.0.0/0'

        New-EC2SecurityGroup -GroupName $SecurityGroupName  -Description "Test Security Group"
        
        Write-Host 'Opening firewall for ping'
        Grant-EC2SecurityGroupIngress -GroupName $SecurityGroupName -IpPermissions @{IpProtocol = "icmp"; FromPort = -1; ToPort = -1; IpRanges = @($myIpRange)}
        
        Write-Host 'Opening firewall for RDP'
        Grant-EC2SecurityGroupIngress -GroupName $SecurityGroupName -IpPermissions @{IpProtocol = "tcp"; FromPort = 3389; ToPort = 3389; IpRanges = @($myIpRange)}
        Grant-EC2SecurityGroupIngress -GroupName $SecurityGroupName -IpPermissions @{IpProtocol = "udp"; FromPort = 3389; ToPort = 3389; IpRanges = @($myIpRange)}
        
        Write-Host 'Opening firewall for WinRM'
        Grant-EC2SecurityGroupIngress -GroupName $SecurityGroupName -IpPermissions @{IpProtocol = "tcp"; FromPort = 5985; ToPort = 5986; IpRanges = @($myIpRange)}
    }

    function New-KeyPair
    {
        [CmdletBinding(PositionalBinding = $false)]
        param (
            [Parameter(Mandatory = $false)]
            [string] $KeyName
        )

        if ([string]::IsNullOrWhiteSpace($KeyName))
        {
            throw [ArgumentException]::new("The name of key for encryption of Administrator password must be specified.", 'KeyName')
        }
        
        if (Get-EC2KeyPair | ? { $_.KeyName -eq $KeyName })
        {
            Write-Host "Key ""$KeyName"" exists, skipping."
            return
        }
        
        [Amazon.EC2.Model.KeyPair] $keyPair = New-EC2KeyPair -KeyName $KeyName
        [string] $keyFilePath = [IO.Path]::Combine($PSScriptRoot, "$KeyName.pem")
        Write-Host "Backing up key: ""$keyFilePath""."

        if ( Test-Path $keyFilePath -PathType Leaf )
        {
            Write-Host "Removing stale file: ""$keyFilePath""."
            Remove-Item -LiteralPath $keyFilePath -Force
        }
        
        "$($keyPair.KeyMaterial)" | Out-File -Encoding ascii -FilePath $keyFilePath
        "KeyName: $($keyPair.KeyName)" | Out-File -Encoding ascii -FilePath $keyFilePath -Append
        "KeyFingerprint: $($keyPair.KeyFingerprint)" | Out-File -Encoding ascii -FilePath $keyFilePath -Append
    }

    function Get-ImageId
    {
        [Object[]]$amiObj = Get-EC2Image -Filter @{ Name="name"; Values="ubuntu*" } -Owner amazon
        if ($amiObj.Count -lt 1)
        {
            throw [Exception]::new('Failed to find ubuntu AMI')    
        }
        
        return $amiObj[0].ImageId 
    }
}
PROCESS
{
    New-SecurityGroup -SecurityGroupName $securityGroup
    New-KeyPair -KeyName $keyName
    [ValidateNotNullOrEmpty()][string] $imageId = Get-ImageId
    
    [Amazon.EC2.Model.Reservation] $ec2Instance = New-EC2Instance -ImageId $imageId -MinCount 1 -MaxCount 1 -KeyName $keyName -SecurityGroups $securityGroup -InstanceType $instanceType

    [ValidateNotNullOrEmpty()][string] $instanceId = $ec2Instance.Instances[0].InstanceId

    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ((Get-EC2Instance -InstanceId $instanceId).Instances[0].State.Name -ine 'Running')
    {
        Write-Host "Waiting for instance ""$instanceId"" enter running state."
        if ($timer.Elapsed -ge [timespan]::FromMinutes(30))
        {
            throw [Exception]::new("Timeout exceeded. Instance ""$instanceId"" failed to enter running state.")
        }
        Start-Sleep -Seconds 30
    }
    Write-Host "Instance ""$instanceId"" is running."
    $timer.Stop()

    [ValidateNotNullOrEmpty()][string] $publicDnsName = (Get-EC2Instance -InstanceId $instanceId).Instances[0].PublicDnsName
    Write-Host "Waiting for instance ""$instanceId"" has DNS name:""$publicDnsName""."

    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Connection -Quiet -ComputerName $publicDnsName -Count 1))
    {
        Write-Host "Waiting for ping response from ""$publicDnsName""."
        if ($timer.Elapsed -ge [timespan]::FromMinutes(15))
        {
            throw [Exception]::new("Timeout exceeded. ""$publicDnsName"" failed to respond to ping command.")
        }
        Start-Sleep -Seconds 10
    }
    $timer.Stop()
    Write-Host "Instance online: ""$publicDnsName""."
}

