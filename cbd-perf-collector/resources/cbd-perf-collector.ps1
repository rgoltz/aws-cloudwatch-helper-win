<# 
.SYNOPSIS CloudBerry Drive performance probs with AWS CloudWatch integration
.DESCRIPTION CloudBerry Drive performance checks with AWS CloudWatch integration using Copy-Item / Compare-Object and Remove-Item
.NOTES This PowerShell script was developed and optimized for ScriptRunner. 
The script will generate a random filename/filecontent along a fixed filesize.
The time (in ms) to Copy and Remove a file will be collected and pushed to CloudWatch Metric.
The content of the orginal file and the file after copy to CloudBerry will be compared and result will be pushed to a CloudWatch Metric as well.
Version:
- 1.0 Robert Goltz: initial version without awscli/put-metric-data after local testing finished successfully
- 1.1 Robert Goltz: define Get-Content / read-operation as dedicated check
- 2.0 Robert Goltz: adding awscli cmds for cloudwatch put-metric-data for WriteLatency, ReadLatency, DeleteLatency
.LINK https://github.com/<to-be-uploaded>
#>

# TODO: check if local folder exists (LocalWindows*)
# TODO: impl check for target-folder (to avoid typos or issues with Remove-part of the script)
# TODO: impl logfile rolling/housekeeping
# TODO: check, if there is already an instance of the script is running = lock-file
# TODO: if diff is not OK, copy both files to a dlq folder to enable further checks


$localHostname = [System.Net.Dns]::GetHostName()

#################
# set up here
#################
# !! do not add "\" on the end of the following variables:
# local folder, e.g. on C-drive
$LocalWindowsDriveFolder = "D:\CloudWatch_cbd-perf-collector\temp"
##$LocalWindowsDriveFolder = "C:\temp\cbd-source"
# folder on CloudBerry Drive, e.g. F-drive
$CloudBerryDriveFolder = "F:\PKSPG_SFS\att"
##$CloudBerryDriveFolder = "C:\temp\cbd-target"
# local folder for logging if this script
$LocalWindowsLogFolder = "D:\CloudWatch_cbd-perf-collector\logs"
##$LocalWindowsLogFolder = "C:\temp\cbd-perf-collector-logs"


#####
# cloudwatch settings
#####
# note: level within CloudWatch metric within AWS Console:
    # (1st level) namespace:  => cloudwatchRegion
    # (2nd level) dimensions: => cloudwatchDimension
    # (3rd level) tableview:  => stepScope
$cloudwatchRegion = "eu-central-1"
$cloudwatchMetricname = "elokpkh-Win-CloudBerryDrive-CustomMetrics"
$instanceId = (Invoke-WebRequest -Uri http://169.254.169.254/latest/meta-data/instance-id).content


####################################

# https://github.com/awslabs/aws-systems-manager/blob/master/Community/101-SSH-PowerShell-Remoting/install.ps1
function Write-Log {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string] $Message
  )
  Add-Content -Path $LocalWindowsLogFolder\cbd-perf-collector.log -Value ('{0}: {1}' -f (Get-Date -Format o), $Message)
}


# https://powershell.org/forums/topic/generating-a-20-character-hex-string-with-powershell/ (by Bart Verkoeijen)
function Get-RandomHex {
    param(
        [int] $Bits = 256
    )
    $bytes = new-object 'System.Byte[]' ($Bits/8)
    (new-object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes)
    (new-object System.Runtime.Remoting.Metadata.W3cXsd2001.SoapHexBinary @(,$bytes)).ToString()
}


####################################

#################
# step 0: generate file with random content (by having a fixed content-size)
#################

Write-Log -Message "---> START: starting PowerShell script on $localHostname & generating filename/filecontent ..."
# generate and set random filename (e.g. A19E2C348E6BFF373172131F6A1241.txt = 123 Bits)
$randomFileNameHex = Get-RandomHex -Bits 123
# generate and set random filecontent (602 KB (617.290 Bytes) = 1234567 Bits)
$randomFileContentLocalHex = Get-RandomHex -Bits 1234567
$randomFileContentLocalHex | Out-File -FilePath "$LocalWindowsDriveFolder\$randomFileNameHex.txt"

# set variables with full path and filename
$SourcePathAndFile = "$LocalWindowsDriveFolder\$randomFileNameHex.txt"
$DestinationPathAndFile = "$CloudBerryDriveFolder\$randomFileNameHex.txt"



#################
# step 1: write file to CloudBerry Drive folder and track time for this step in ms
#################
$stepScope = "WriteLatency"
$cloudwatchDimension = "CloudBerryMonitoringScope=PerformanceProbe"
$stopwatch = New-Object System.Diagnostics.Stopwatch
$stopwatch.Start()
Try
{
    Copy-Item -Path $SourcePathAndFile -Destination $DestinationPathAndFile -ErrorAction Stop
    $stopwatch.Stop()
    $CopyStepElapsedMilliseconds = $stopwatch.ElapsedMilliseconds
    Write-Log -Message " OK: Copy-Item from: $SourcePathAndFile OK after $CopyStepElapsedMilliseconds ms to: $DestinationPathAndFile."
    aws cloudwatch put-metric-data --metric-name "$stepScope" --namespace "$cloudwatchMetricname" --dimensions "InstanceId=$instanceId,$cloudwatchDimension" --unit Milliseconds --value $CopyStepElapsedMilliseconds --region "$cloudwatchRegion"  
    Write-Log -Message "  --> CloudWatch -> $stepScope : $CopyStepElapsedMilliseconds for cmd Copy-Item pushed to CloudWatch (see metric: $cloudwatchMetricname -> $cloudwatchDimension)."
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    $stopwatch.Stop()
    $FailedElapsedMilliseconds = $stopwatch.ElapsedMilliseconds
    Write-Log -Message " ERROR-catched: Copy-Item failed with $ErrorMessage on $FailedItem after $FailedElapsedMilliseconds ms."
}




#################
# step 2: read file from CloudBerry Drive folder and track time for this step in ms
#################
$stepScope = "ReadLatency"
$cloudwatchDimension = "CloudBerryMonitoringScope=PerformanceProbe"
$stopwatch = New-Object System.Diagnostics.Stopwatch
$stopwatch.Start()
Try
{
    $ContentTargetFile = Get-Content $DestinationPathAndFile
    $stopwatch.Stop()
    $ReadStepElapsedMilliseconds = $stopwatch.ElapsedMilliseconds
    Write-Log -Message " OK: Get-Content from: $DestinationPathAndFile OK after $CopyStepElapsedMilliseconds ms."
    aws cloudwatch put-metric-data --metric-name "$stepScope" --namespace "$cloudwatchMetricname" --dimensions "InstanceId=$instanceId,$cloudwatchDimension" --unit Milliseconds --value $ReadStepElapsedMilliseconds --region "$cloudwatchRegion"  
    Write-Log -Message "  --> CloudWatch -> $stepScope : $ReadStepElapsedMilliseconds for cmd Copy-Item pushed to CloudWatch (see metric: $cloudwatchMetricname -> $cloudwatchDimension)."
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    $stopwatch.Stop()
    $FailedElapsedMilliseconds = $stopwatch.ElapsedMilliseconds
    Write-Log -Message " ERROR-catched: Get-Content failed with $ErrorMessage on $FailedItem after $FailedElapsedMilliseconds ms."
}




#################
# step 3: compare the content of local file against the content of file, which has been written to CloudBerry Drive folder before
#################
$stepScope = "IsContentSame"
$cloudwatchDimension = "CloudBerryMonitoringScope=IntegrityProbe"
Try
{
    $ContentSourceFile = $randomFileContentLocalHex
    #ContentTargetFile is already set above for reading the file from CloudBerry
    if (Compare-Object $ContentSourceFile $ContentTargetFile)  {
        Write-Log -Message " WARN: Compare-Object - content of both files are NOT the same!"
        # awscli put-metric-data for 1, since strings are different
        Write-Log -Message "  --> CloudWatch-compareFileContentResult value: 1 (= DIFF) pushed to CloudWatch."
    } Else {
        Write-Log -Message " OK: Compare-Object - content of both files are the same!"
        # awscli put-metric-data for 0, since strings are the same
        Write-Log -Message "  --> CloudWatch-compareFileContentResult value: 0 (= SAME) pushed to CloudWatch."
    } 
}
Catch
{
    $FailedItem = $_.Exception.ItemName
    $FailedElapsedMilliseconds = $stopwatch.ElapsedMilliseconds
    Write-Log -Message " ERROR-catched: Compare-Object failed with $ErrorMessage on $FailedItem"
}




#################
# step 4: delete file from CloudBerry Drive folder and track time for this step in ms
#################
$stepScope = "DeleteLatency"
$cloudwatchDimension = "CloudBerryMonitoringScope=PerformanceProbe"
$stopwatch = New-Object System.Diagnostics.Stopwatch
$stopwatch.Start()
Try
{
    Remove-Item -Path $DestinationPathAndFile -ErrorAction Stop
    $stopwatch.Stop()
    $RemoveStepElapsedMilliseconds = $stopwatch.ElapsedMilliseconds
    Write-Log -Message " OK: Remove-Item $DestinationPathAndFile OK after $RemoveStepElapsedMilliseconds ms."
    aws cloudwatch put-metric-data --metric-name "$stepScope" --namespace "$cloudwatchMetricname" --dimensions "InstanceId=$instanceId,$cloudwatchDimension" --unit Milliseconds --value $RemoveStepElapsedMilliseconds --region "$cloudwatchRegion"  
    Write-Log -Message "  --> CloudWatch -> $stepScope : $RemoveStepElapsedMilliseconds for cmd Copy-Item pushed to CloudWatch (see metric: $cloudwatchMetricname -> $cloudwatchDimension)."
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    $stopwatch.Stop()
    $FailedElapsedMilliseconds = $stopwatch.ElapsedMilliseconds
    Write-Log -Message " ERROR-catched: Remove-Item failed with $ErrorMessage on $FailedItem after $FailedElapsedMilliseconds ms"
}

# Remove local file
Remove-Item -Path $SourcePathAndFile
Write-Log -Message "<--- END: end."