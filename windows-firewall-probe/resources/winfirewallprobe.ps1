<#
.SYNOPSIS Windows Firewall Probe / Watchdog
.DESCRIPTION Windows Firewall checks collecting state of local Windows Firwall and push this information to CloudWatch (Metric)
.NOTES The script will query Windows Firewall Status and push this information into a CloudWatch Metric - If the state is expected (=disabled), it's always pushed as 0/zero. Firewall-Settings are defined as AWS SecurityGroups in CloudFormation.
Version:
- 1.0 Robert Goltz: initial version with checks on GPO- and localhost-PolicyStore via PowerShell + check current Registry value
.LINK https://github.com/rgoltz/aws-cloudwatch-helper-win/windows-firewall-probe/
#>


$localHostname = [System.Net.Dns]::GetHostName()


# local folder for logging the results/status if this script here
$LocalWindowsLogFolder = "D:\BFTools\CloudWatch-Custom\WinFirewallStatusProbe\logs"
If(!(test-path $LocalWindowsLogFolder))
{
      New-Item -ItemType "directory" -Path "$LocalWindowsLogFolder"
}


$cloudwatchRegion = "eu-central-1"
$cloudwatchMetricname = "Windows-CustomMetrics"
$instanceId = (Invoke-WebRequest -Uri http://169.254.169.254/latest/meta-data/instance-id).content


####################################

# https://github.com/awslabs/aws-systems-manager/blob/master/Community/101-SSH-PowerShell-Remoting/install.ps1 (by Trevor Sullivan)
function Write-Log {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string] $Message
  )
  Add-Content -Path $LocalWindowsLogFolder\winfirewall-probe.log -Value ('{0}: {1}' -f (Get-Date -Format o), $Message)
}


# Module for using native AWS Commands in Powershell
Import-Module AWSPowerShell

# Creating and returning a MetricDatum Object with provided Params
# https://docs.aws.amazon.com/sdkfornet/v3/apidocs/index.html?page=CloudWatch/TCloudWatchMetricDatum.html&tocid=Amazon_CloudWatch_Model_MetricDatum
function CreateMetric {
    param(
        [string] $MetricName,
        [Amazon.CloudWatch.Model.Dimension[]] $Dimensions,
        [string] $Unit,
        [string] $Value
    )
    $metric = New-Object Amazon.CloudWatch.Model.MetricDatum
    $metric.Dimensions = $Dimensions
    $metric.Timestamp = (Get-Date).ToUniversalTime()
    $metric.MetricName = $MetricName
    $metric.Unit = $Unit
    $metric.Value = $Value
    return $metric
}

# Creating and returning a Dimension Object with provided Params
# https://docs.aws.amazon.com/sdkfornet/v3/apidocs/index.html?page=CloudWatch/TCloudWatchMetricDatum.html&tocid=Amazon_CloudWatch_Model_MetricDatum
function CreateDimension {
    param(
        [string] $DimensionName,
        [string] $DimensionValue
    )
    $dimension = New-Object Amazon.CloudWatch.Model.Dimension
    $dimension.Name = $DimensionName
    $dimension.Value = $DimensionValue

    return $dimension
}

# Enum to distinguish between the different metrics, in case we need this later to distinguish between different checks.
# Currently we use one global metric to collect all OK-values (0)
enum MetricType {
    WindowsFirewallChecker
}

# Creating two MetricDatum Objects, which get transmitted to AWS Cloudwatch
function WriteAllMetrics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [MetricType] $MetricType,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Unit,

        [Parameter(Mandatory)]
        [string] $Value
    )
    Process {
        $Dimension1Name = "WindowsFirewallProbe"
        $Dimension2Name = "InstanceId"

        $Dimension1Value = "StatusBoolean"
        $Dimension2Value = $InstanceId

        $MetricName = $MetricType

        # Create first instancespecific metric with dimension 1 & 2 (will be used to identify the affecting instance after an alert)
        $dim1 = CreateDimension -DimensionName $Dimension1Name -DimensionValue $Dimension1Value
        $dim2 = CreateDimension -DimensionName $Dimension2Name -DimensionValue $Dimension2Value
        $metric1 = CreateMetric -MetricName $MetricName -Unit $Unit -Value $Value -Dimensions $dim1,$dim2
        
        # create second aggregated metric with dimension 1 only (will be used for alerting)
        $metric2 = CreateMetric -MetricName $MetricName -Unit $Unit -Value $Value -Dimensions $dim1
        
        # sending data to cloudwatch and returning possible Errorcodes (should be null)
        return Write-CWMetricData -Namespace $cloudwatchMetricname -Region $cloudwatchRegion -MetricData $metric1,$metric2

    }
}


####################################

Write-Log -Message "START - *** WindowsFirewallProbe *** $localHostname ***********************************************"

# notes:
# * However, even after turning OFF Windows Firewall State for Domain Profile, netsh advfirewall show domainprofile still shows that the state of firewall is still O


#################
# check 1-1: check GPO active state for Domain
#################
$checkScope = "WinFirewallStatusGpoDomain"
Try
{
    $checkCurrentSettingGpoDomain = Get-NetfirewallProfile -PolicyStore ActiveStore -Name Domain | Select -expand "Enabled"
    # 

    if ($checkCurrentSettingGpoDomain){
        Write-Log -Message "$checkScope     : result from NetfirewallProfile GPO is NOT ok (checkresult true), since NOT expected value Enabled found: [$checkCurrentSettingGpoDomain] => CW=1"
        WriteAllMetrics -MetricType ([MetricType]::WindowsFirewallChecker) -Unit Count -Value 1
        Write-Log -Message "$checkScope     : --> CloudWatch -> $checkScope : pushed to CloudWatch (see metric: $cloudwatchMetricname -> $cloudwatchDimension)."
    }
    else {
        Write-Log -Message "$checkScope     : result from NetfirewallProfile GPO is OK (false), since Enabled-check returned false: [$checkCurrentSettingGpoDomain] => We want this! - CW=0 (and sent this to CloudWatch)"
        WriteAllMetrics -MetricType ([MetricType]::WindowsFirewallChecker) -Unit Count -Value 0
    }
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    Write-Log -Message "$checkScope     : ERROR-catched: query status and push to CloudWatch failed with: $ErrorMessage"
}


#################
# check 1-2: check GPO active state for Private
#################
$checkScope = "WinFirewallStatusGpoPrivate"
Try
{
    $checkCurrentSettingGpoPrivate = Get-NetfirewallProfile -PolicyStore ActiveStore -Name Private | Select -expand "Enabled"
    # 

    if ($checkCurrentSettingGpoPrivate){
        Write-Log -Message "$checkScope    : result from NetfirewallProfile GPO is NOT ok (checkresult true), since NOT expected value Enabled found: [$checkCurrentSettingGpoPrivate] => CW=1"
        WriteAllMetrics -MetricType ([MetricType]::WindowsFirewallChecker) -Unit Count -Value 1
        Write-Log -Message "$checkScope     : --> CloudWatch -> $checkScope : pushed to CloudWatch (see metric: $cloudwatchMetricname -> $cloudwatchDimension)."
    }
    else {
        Write-Log -Message "$checkScope    : result from NetfirewallProfile GPO is OK (false), since Enabled-check returned false: [$checkCurrentSettingGpoPrivate] => We want this! - CW=0 (and sent this to CloudWatch)"
        WriteAllMetrics -MetricType ([MetricType]::WindowsFirewallChecker) -Unit Count -Value 0
    }
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    Write-Log -Message "$checkScope    : ERROR-catched: query status and push to CloudWatch failed with: $ErrorMessage"
}


#################
# check 1-3: check GPO active state for Public
#################
$checkScope = "WinFirewallStatusGpoPublic"
Try
{
    $checkCurrentSettingGpoPublic = Get-NetfirewallProfile -PolicyStore ActiveStore -Name Public | Select -expand "Enabled"
    # 

    if ($checkCurrentSettingGpoPublic){
        Write-Log -Message "$checkScope     : result from NetfirewallProfile GPO is NOT ok (checkresult true), since NOT expected value Enabled found: [$checkCurrentSettingGpoPublic] => CW=1"
        WriteAllMetrics -MetricType ([MetricType]::WindowsFirewallChecker) -Unit Count -Value 1
        Write-Log -Message "$checkScope     : --> CloudWatch -> $checkScope : pushed to CloudWatch (see metric: $cloudwatchMetricname -> $cloudwatchDimension)."
    }
    else {
        Write-Log -Message "$checkScope     : result from NetfirewallProfile GPO is OK (false), since Enabled-check returned false: [$checkCurrentSettingGpoPublic] => We want this! - CW=0 (and sent this to CloudWatch)"
        WriteAllMetrics -MetricType ([MetricType]::WindowsFirewallChecker) -Unit Count -Value 0
    }
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    Write-Log -Message "$checkScope    : ERROR-catched: query status and push to CloudWatch failed with: $ErrorMessage"
}


#################
# check 2-1: check localhost status - Domain
#################
$checkScope = "WinFirewallStatusLocalDomain"
Try
{
    $checkLocalSettingDomainViaPs = Get-NetfirewallProfile -PolicyStore localhost -Name Domain | Select -expand "Enabled"

    if ($checkLocalSettingDomainViaPs -like 'NotConfigured'){
        Write-Log -Message "$checkScope   : result is OK, since localhost NetfirewallProfile should be in state not configured [$checkLocalSettingDomainViaPs] => We want this! - CW=0 (and sent this to CloudWatch)"
        WriteAllMetrics -MetricType ([MetricType]::WindowsFirewallChecker) -Unit Count -Value 0
    }
    else {
        Write-Log -Message "$checkScope   : value is not expected, hence localhost NetfirewallProfile has some other state - It's: [$checkLocalSettingDomainViaPs] => CW=1"
        WriteAllMetrics -MetricType ([MetricType]::WindowsFirewallChecker) -Unit Count -Value 1
        Write-Log -Message "$checkScope   : --> CloudWatch -> $checkScope : pushed to CloudWatch (see metric: $cloudwatchMetricname -> $cloudwatchDimension)."
    }
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    Write-Log -Message "$checkScope  : ERROR-catched: query status and push to CloudWatch failed with: $ErrorMessage"
}


#################
# check 2-2: check localhost status - Private
#################
$checkScope = "WinFirewallStatusLocalPrivate"
Try
{
    $checkLocalSettingPrivateViaPs = Get-NetfirewallProfile -PolicyStore localhost -Name Private | Select -expand "Enabled"

    if ($checkLocalSettingPrivateViaPs -like 'NotConfigured'){
        Write-Log -Message "$checkScope  : result is OK, since localhost NetfirewallProfile should be in state not configured [$checkLocalSettingPrivateViaPs] => We want this! - CW=0 (and sent this to CloudWatch)"
        WriteAllMetrics -MetricType ([MetricType]::WindowsFirewallChecker) -Unit Count -Value 0
    }
    else {
        Write-Log -Message "$checkScope  : value is not expected, hence localhost NetfirewallProfile has some other state - It's: [$checkLocalSettingPrivateViaPs] => CW=1"
        WriteAllMetrics -MetricType ([MetricType]::WindowsFirewallChecker) -Unit Count -Value 1
        Write-Log -Message "$checkScope  : --> CloudWatch -> $checkScope : pushed to CloudWatch (see metric: $cloudwatchMetricname -> $cloudwatchDimension)."
    }
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    Write-Log -Message "$checkScope  : ERROR-catched: query status and push to CloudWatch failed with: $ErrorMessage"
}


#################
# check 2-3: check localhost status - Public
#################
$checkScope = "WinFirewallStatusLocalPublic"
Try
{
    $checkLocalSettingPublicViaPs = Get-NetfirewallProfile -PolicyStore localhost -Name Public | Select -expand "Enabled"

    if ($checkLocalSettingPublicViaPs -like 'NotConfigured'){
        Write-Log -Message "$checkScope   : result is OK, since localhost NetfirewallProfile should be in state not configured [$checkLocalSettingPublicViaPs] => We want this! - CW=0 (and sent this to CloudWatch)"
        WriteAllMetrics -MetricType ([MetricType]::WindowsFirewallChecker) -Unit Count -Value 0
    }
    else {
        Write-Log -Message "$checkScope   : value is not expected, hence localhost NetfirewallProfile has some other state - It's: [$checkLocalSettingPublicViaPs] => CW=1"
        WriteAllMetrics -MetricType ([MetricType]::WindowsFirewallChecker) -Unit Count -Value 1
        Write-Log -Message "$checkScope   : --> CloudWatch -> $checkScope : pushed to CloudWatch (see metric: $cloudwatchMetricname -> $cloudwatchDimension)."
    }
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    Write-Log -Message "$checkScope   : ERROR-catched: query status and push to CloudWatch failed with: $ErrorMessage"
}


#################
# check 3: get status from registry
#################
$checkScope = "WinFirewallStatusLocalRegistry"
Try
{
    $checkLocalSettingViaRegEdit = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpsdrv | Select -expand "Start"

    if ($checkLocalSettingViaRegEdit -eq 3){
        # it's value 3 - info: 4 is disabled / 2 is enabled
        Write-Log -Message "$checkScope : result with value 3 in registry - this is expected - value: [$checkLocalSettingViaRegEdit] => We want this! - CW=0 (and sent this to CloudWatch)"
        WriteAllMetrics -MetricType ([MetricType]::WindowsFirewallChecker) -Unit Count -Value 0
    }
    else {
        Write-Log -Message "$checkScope : value in registry is not expected - hence it's some other state/value: [$checkLocalSettingViaRegEdit] => CW=1"
        WriteAllMetrics -MetricType ([MetricType]::WindowsFirewallChecker) -Unit Count -Value 1
        Write-Log -Message "$checkScope : --> CloudWatch -> $checkScope : pushed to CloudWatch (see metric: $cloudwatchMetricname -> $cloudwatchDimension)."
    }
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    Write-Log -Message "$checkScope : ERROR-catched: query status and push to CloudWatch failed with: $ErrorMessage"
}


###############################################################################
# Simple LogFile-Housekeeping (based on the amount of lines inside the logfile)
$maxlines = 5000
$logfile = "$LocalWindowsLogFolder\winfirewall-probe.log"

(Get-Content $logfile -tail $maxlines -readcount 0) |
 Set-Content $logfile


Write-Log -Message "*********************************************** END - *** WindowsFirewallProbe *** $localHostname"
