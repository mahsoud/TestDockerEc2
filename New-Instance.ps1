#Requires -Version 5

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
    $Script:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    Set-StrictMode -Version 1

    if (-not (Get-Module -Listavailable -Name AWSPowerShell))
    {
        Install-Module -Name AWSPowerShell -Force
    }
    Import-Module AWSPowerShell

    Initialize-AWSDefaults -AccessKey $AccessKey -SecretKey $SecretAccessKey -Region $Region

    Set-Item WSMan:\localhost\Client\TrustedHosts "*" -Force

    [string] $instanceType = 't2.micro'
    [string] $securityGroup = 'mySecGroup'
    [string] $keyName = 'myKey'

    functon New-SecurityGroup
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

        [string] $myIpRange = '0.0.0.0/0'
        $groupId = New-EC2SecurityGroup $SecurityGroupName  -Description "Test Security Group"
        Get-EC2SecurityGroup -GroupNames $SecurityGroupName

        Write-Verbose 'Opening firewall for ping'
        Grant-EC2SecurityGroupIngress -GroupName $SecurityGroupName -IpPermissions @{IpProtocol = "icmp"; FromPort = -1; ToPort = -1; IpRanges = @($myIpRange)}
        
        Write-Verbose 'Opening firewall for RDP'
        Grant-EC2SecurityGroupIngress -GroupName $SecurityGroupName -IpPermissions @{IpProtocol = "tcp"; FromPort = 3389; ToPort = 3389; IpRanges = @($myIpRange)}
        Grant-EC2SecurityGroupIngress -GroupName $SecurityGroupName -IpPermissions @{IpProtocol = "udp"; FromPort = 3389; ToPort = 3389; IpRanges = @($myIpRange)}
        
        Write-Verbose 'Opening firewall for WinRM'
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

        $keyPair = New-EC2KeyPair -KeyName $KeyName
        $keyFilePath = [IO.Path]::Combine($PSScriptRoot, "$KeyName.pem")

        if ( Test-Path $keyFilePath -PathType Leaf )
        {
            Remove-Item -LiteralPath $keyFilePath -Force
        }

        "$($keyPair.KeyMaterial)" | Out-File -Encoding ascii -FilePath $keyFilePath
        "KeyName: $($keyPair.KeyName)" | Out-File -Encoding ascii -FilePath $keyFilePath -Append
        "KeyFingerprint: $($keyPair.KeyFingerprint)" | Out-File -Encoding ascii -FilePath $keyFilePath -Append

        return $keyPair
    }
}
PROCESS
{
    New-SecurityGroup -SecurityGroupName $securityGroup
    $keyPair = New-KeyPair -KeyName $keyName
    
    [Object[]]$amiObj = Get-EC2Image -Filter @{ Name="name"; Values="ubuntu*" } -Owner amazon

    if ($amiObj.Count -lt 1)
    {
        throw [Exception]::new('Failed to find ubuntu AMI')    
    }

    $ec2Instance = New-EC2Instance -ImageId $amiObj[0].ImageId -MinCount 1 -MaxCount 1 -KeyName $keyPair -SecurityGroups $securityGroup -InstanceType $instanceType

    $instanceId = $ec2Instance.Instances[0].InstanceId

    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ((Get-EC2Instance -Filter $instaceFilter).Instances[0].State.Name -ine 'Running')
    {
        Write-Verbose -Message "Waiting for instance ""$instanceId"" enter running state."
        if ($timer.Elapsed -ge [timespan]::FromMinutes(15))
        {
            throw [Exception]::new("Timeout exceeded. Instance ""$instanceId"" failed to enter running state.")
        }
        Start-Sleep -Seconds 30
    }
    $timer.Stop()
}

