﻿#Requires -Version 5
#Requires -RunAsAdministrator

using namespace System
using namespace Amazon

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
begin
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

    [string] $instanceType = 't2.micro'
    [string] $securityGroup = 'mySecGroup'
    [string] $keyName = 'myKey'
    [string] $loadBalancerName = 'myElbClassic'
    [int] $InstanceCount = 2

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

        if (Get-EC2SecurityGroup | ? { $_.GroupName -eq $SecurityGroupName })
        {
            Write-Host "Security group ""$SecurityGroupName"" exists, skipping."
            return
        }

        [string] $myIpRange = '0.0.0.0/0'
        Write-Host 'Setting up new security group.'

        New-EC2SecurityGroup -GroupName $SecurityGroupName  -Description "Test Security Group"
        
        Write-Host 'Opening firewall for ping'
        Grant-EC2SecurityGroupIngress -GroupName $SecurityGroupName -IpPermissions @{IpProtocol = "icmp"; FromPort = -1; ToPort = -1; IpRanges = @($myIpRange)}
        
        Write-Host 'Opening firewall for RDP'
        Grant-EC2SecurityGroupIngress -GroupName $SecurityGroupName -IpPermissions @{IpProtocol = "tcp"; FromPort = 22; ToPort = 22; IpRanges = @($myIpRange)}
        Grant-EC2SecurityGroupIngress -GroupName $SecurityGroupName -IpPermissions @{IpProtocol = "udp"; FromPort = 22; ToPort = 22; IpRanges = @($myIpRange)}
        
        Write-Host 'Opening firewall for HTTP and HTTPS'
        Grant-EC2SecurityGroupIngress -GroupName $SecurityGroupName -IpPermissions @{IpProtocol = "tcp"; FromPort = 80; ToPort = 80; IpRanges = @($myIpRange)}
        Grant-EC2SecurityGroupIngress -GroupName $SecurityGroupName -IpPermissions @{IpProtocol = "tcp"; FromPort = 443; ToPort = 443; IpRanges = @($myIpRange)}
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

        Write-Host 'Setting up new key.'
        [EC2.Model.KeyPair] $keyPair = New-EC2KeyPair -KeyName $KeyName
        
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

    function New-LoadBalancer
    {
        [CmdletBinding(PositionalBinding = $false)]
        param (
            [Parameter(Mandatory = $false)]
            [string] $LoadBalancerName,
            [Parameter(Mandatory = $false)]
            [string] $SecurityGroupName
        )

        if ([string]::IsNullOrWhiteSpace($LoadBalancerName))
        {
            throw [ArgumentException]::new("The name of the load balacer must be specified.", 'Url')
        }
        
        if (Get-ELBLoadBalancer | ? { $_.LoadBalancerName -eq $LoadBalancerName })
        {
            Write-Host "Load Balancer ""$LoadBalancerName"" exists, skipping."
            return
        }

        Write-Host "Creating new load balancer with listener on HTTP port 80."
        [ElasticLoadBalancing.Model.Listener] $httpListener = [ElasticLoadBalancing.Model.Listener]::new('http', 80, 80)
        New-ELBLoadBalancer -LoadBalancerName $LoadBalancerName -SecurityGroup $((Get-EC2SecurityGroup -GroupName $SecurityGroupName).GroupId) -Listener $httpListener -Subnet $((Get-EC2Subnet).SubnetId)
    }

    function Wait-TaskCompletion
    {
        [CmdletBinding(PositionalBinding = $false)]
        param (
            [Parameter(Mandatory = $false)]
            [string] $ConditionalStatement,
            [Parameter(Mandatory = $false)]
            [int] $DelayInSeconds = 15,
            [Parameter(Mandatory = $false)]
            [int] $TimeoutInMin = 3
        )
                
        if ([string]::IsNullOrWhiteSpace($ConditionalStatement))
        {
            throw [ArgumentException]::new("The conditional statement must be specified.", 'ConditionalStatement')
        }
        if ($DelayInSeconds -le 0)
        {
            throw [ArgumentException]::new("The delay between polls should be greater then 0 seconds.", 'DelayInSeconds')
        }
        if ($TimeoutInMin -lt 1)
        {
            throw [ArgumentException]::new("The timeout for action should be at least a minute.", 'TimeoutInMin')
        }
        
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while (Invoke-Expression -Command $ConditionalStatement)
        {
            if ($timer.Elapsed -ge [timespan]::FromMinutes($TimeoutInMin))
            {
                throw [Exception]::new("Timeout ($TimeoutInMin minutes) exceeded without meeting the preset condition.")
            }
            Write-Host "Waiting..."
            Start-Sleep -Seconds $DelayInSeconds
        }
        $timer.Stop()
    }

    function Test-WebPageOffline
    {
        [CmdletBinding(PositionalBinding = $false)]
        param (
            [Parameter(Mandatory = $false)]
            [string] $Url
        )

        if ([string]::IsNullOrWhiteSpace($Url))
        {
            throw [ArgumentException]::new("The URL of the web page must be specified.", 'Url')
        }

        try
        {
            [Int32] $statusCode = (Invoke-WebRequest -UseBasicParsing -Uri $Url).StatusCode
            Write-Host "Got response $statusCode from ""$Url""."
            if ($statusCode -eq 200)
            {
                return $false
            }
            return $true
        }
        catch
        {
            return $false
        }
    }
}
process
{
    New-SecurityGroup -SecurityGroupName $securityGroup
    New-KeyPair -KeyName $keyName
    New-LoadBalancer -LoadBalancerName $loadBalancerName -SecurityGroupName $securityGroup

    [ValidateNotNullOrEmpty()][string] $imageId = Get-ImageId
    
    [ValidateNotNullOrEmpty()][string] $dockerScript = Get-Content -Raw $(Join-Path $PSScriptRoot 'docker.sh' -Resolve)
    [ValidateNotNullOrEmpty()][string] $userData = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($dockerScript))
   
    [EC2.Model.Reservation] $ec2Instance = New-EC2Instance -ImageId $imageId -MinCount $InstanceCount -MaxCount $InstanceCount -KeyName $keyName -SecurityGroups $securityGroup -InstanceType $instanceType -UserData $userData

    [ValidateNotNullOrEmpty()][string[]] $instanceIds = $ec2Instance.Instances.InstanceId

    Write-Host "Registering instances, ""$instanceIds"", with load balancer."
    Register-ELBInstanceWithLoadBalancer -LoadBalancerName $loadBalancerName -Instance $instanceIds
    
    [Collections.Generic.List[string]] $instanceDNSNames = [Collections.Generic.List[string]]::new()

    $instanceIds | % {
        Write-Host "Waiting for instance  ""$_"" to enter running state."
        Wait-TaskCompletion -ConditionalStatement "(Get-EC2Instance -InstanceId $_).Instances[0].State.Name -ine 'Running'"

        [ValidateNotNullOrEmpty()][string] $publicDnsName = (Get-EC2Instance -InstanceId $_).Instances[0].PublicDnsName
        Write-Host "DNS name for instance:""$publicDnsName""."
        $instanceDNSNames.Add($publicDnsName)
    }

    $instanceDNSNames | % {
        Write-Host "Waiting for ping response from ""$_""."
        Wait-TaskCompletion -ConditionalStatement "-not (Test-Connection -Quiet -ComputerName $_ -Count 1)"
        Write-Host "Instance is online, ""$_""."
    }

    $instanceDNSNames | % {
        [ValidateNotNullOrEmpty()][string] $nginxUrl = "http://$_"
        Write-Host "Waiting for response from ""$nginxUrl""."
        Wait-TaskCompletion -ConditionalStatement "Test-WebPageOffline -Url $nginxUrl"
        Write-Host "Web page is available: ""$nginxUrl""."
    }

    [ValidateNotNullOrEmpty()][string] $LoadBalancerDnsName = (Get-ELBLoadBalancer -LoadBalancerName $LoadBalancerName).DNSName
    [string] $LoadBalancerUrl = "http://$LoadBalancerDnsName"

    Write-Host "Confirming Web page is available via load balancer url: ""$LoadBalancerUrl""."
    if (Test-WebPageOffline -Url $LoadBalancerUrl)
    {
        throw [Exception]::new("Failed to reach the web page via ""$LoadBalancerUrl"".")
    }
    Write-Host 'DONE.'
}