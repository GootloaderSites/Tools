# filename          : gootloader-detection.ps1
# description       : Detect GootLoader artifacts/IOCs on a Windows system
# author            : @Gootloader
# author            : https://gootloader.zip
# date              : 2023-08-24
# version           : 1.0
# usage             : powershell.exe -ExecutionPolicy Bypass -File gootloader-detector.ps1
# output            : INFECTED_LOG.txt on Desktop, as well as in PowerShell terminal window
#
# Note: Requires Administrator privileges to access Scheduled Tasks of all users
#

# Check if the script is running with administrative privileges
$isAdmin = ([System.Security.Principal.WindowsPrincipal] [System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "This script requires administrative privileges."
    Write-Host "Press Enter to continue..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    # Relaunch the script with elevated privileges
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    Exit
}

Add-Type -AssemblyName System.IO.Compression.FileSystem;

$infectedLog = "$($env:USERPROFILE)\Desktop\INFECTED_LOG.txt";
write-host "Log file will be written to $($infectedLog)"

$confirmation = Read-Host "Do you want to delete Gootloader artifacts? (yes/no)" #Delete artifacts or just detect?
if ($confirmation -eq 'yes') {
    $delete = $true;
    Write-Warning "THERE MIGHT BE ADDITIONAL ARTIFACTS NOT CLEANED UP BY THIS SCRIPT (ex: COLBALT STRIKE BEACON OR REGISTRY ENTRIES)"
    write-warning "THIS SCRIPT IS TO DETECT AND REMOVE GOOTLOADER'S INITIAL ACCESS"
}elseif($confirmation -eq 'no'){
    $delete = $false;
}else{
    write-host "Neither option was selected, defaulting to not delete artifacts";
    $delete = $false;
}

& schtasks /query /v /FO CSV | ConvertFrom-CSV | Where { $_."Task To Run" -like "*wscript*~1.js" } | select TaskName,"Task To Run","Start In" | ForEach-Object { #Run schtasks and filter on ones that have wscript and are pointing to a file ending in ~1.js
    $schtaskName = $_.TaskName -replace "\\", "";
    Write-Warning "Found scheduled task '$($schtaskName)'";
    "Found scheduled task '$($schtaskName)'" | out-file -filepath $infectedLog -Encoding ascii;
    
                
    $partialFN = $_."Task To Run" -split " ";
    $fullDOSpath = "$($_."Start In")\$($partialFN[1])"; #Get the full of the .JS file

    if(Test-Path -Path $fullDOSpath){ #Malicous .JS file found
        write-host "Malicious Javascript file at '$($fullDOSpath)'";
        "Malicious Javascript file at '$($fullDOSpath)'" | out-file -filepath $infectedLog -Encoding ascii -Append;
        if($delete){ #Delete malicious .JS file?
            write-warning "Deleting malicious Javascript file at '$($fullDOSpath)'";
            "Deleting malicious Javascript file at '$($fullDOSpath)'" | out-file -filepath $infectedLog -Encoding ascii -Append;
            Remove-Item -Path $fullDOSpath -force | Out-Null;
        }
    }
    if($delete){ #Delete malicious Scheduled Task?
        write-host "Deleteing scheduled task: '$($schtaskName)'";
        "Deleteing scheduled task: '$($schtaskName)'" | out-file -filepath $infectedLog -Encoding ascii;

        & schtasks /delete /tn $schtaskName /f;
    }

	#This shouldnt be necessary, but just in case the schedule task remains behind, delete it from the disk
    Write-Host "Checking for '$($schtaskName)' file on disk";
    "Checking for '$($schtaskName)' file on disk" | out-file -filepath $infectedLog -Encoding ascii -Append;
    if(Test-Path -Path "$($Env:windir)\Tasks\$($schtaskName)"){
        write-host "Found: $($Env:windir)\Tasks\$($schtaskName)";
        "Found: $($Env:windir)\Tasks\$($schtaskName)" | out-file -filepath $infectedLog -Encoding ascii -Append;
        if($delete){
            write-host "Removing: $($Env:windir)\Tasks\$($schtaskName)";
            "Removing: $($Env:windir)\Tasks\$($schtaskName)" | out-file -filepath $infectedLog -Encoding ascii -Append;
            Remove-Item -Path "$($Env:windir)\Tasks\$($schtaskName)" -force | Out-Null;
        }
    }

    if(Test-Path -Path "$($Env:windir)\System32\Tasks\$($schtaskName)"){
        write-host "Found: $($Env:windir)\System32\Tasks\$($schtaskName)";
        "Found: $($Env:windir)\System32\Tasks\$($schtaskName)" | out-file -filepath $infectedLog -Encoding ascii -Append;

        if($delete){        
            write-host "Removing: $($Env:windir)\System32\Tasks\$($schtaskName)";
            "Removing: $($Env:windir)\System32\Tasks\$($schtaskName)" | out-file -filepath $infectedLog -Encoding ascii -Append;
            Remove-Item -Path "$($Env:windir)\System32\Tasks\$($schtaskName)" -force | Out-Null;
        }
    }
}
write-warning "If you have a large number of users on this system, this process could take a significant amount of time"
$possiblePaths = @("\Documents\","\Desktop\","\Downloads\","\AppData\Local\Google\Chrome\User Data\Default\Cache\","\AppData\Local\Mozilla\Firefox\Profiles\","\AppData\Local\Microsoft\Edge\User Data\Default\Cache\","\AppData\Local\Temp\MicrosoftEdgeDownloads\");

$profiles = Get-ChildItem -Path C:\Users -Directory #Get all user profiles

foreach ($profile in $profiles) { #Start searching all profiles for the original Gootloader .JS or .ZIP file
    foreach ($possiblePath in $possiblePaths) {
        $downloadPath = Join-Path -Path $profile.FullName -ChildPath $possiblePath
        if (Test-Path -Path $downloadPath) {
            foreach ($sourceFile in (Get-ChildItem -Path $downloadPath -Recurse | Where-Object { $_.Name -match ".*\(?\d+\)?\.zip$" })) {
                $files = [System.IO.Compression.ZipFile]::OpenRead($sourceFile.FullName).Entries.FullName
                if ($files.Count -eq 1 -and $files[-1] -eq ".js") {
                    Write-Warning "'$($sourceFile.FullName)' MAY contain a malicious Gootloader Javascript. Recommend running it through Mandiant's Gootloader Decoder here: https://github.com/mandiant/gootloader or https://gootloader.zip/decode-zip-or-js.php"
                    "'$($sourceFile.FullName)' MAY contain a malicious Gootloader Javascript Recommend running it through Mandiant's Gootloader Decoder here: https://github.com/mandiant/gootloader or https://gootloader.zip/decode-zip-or-js.php" | Out-File -FilePath $infectedLog -Encoding ascii -Append

                    $extractedPath = $sourceFile.FullName.Substring(0, $sourceFile.FullName.Length - 4) + "\"
                    Write-Host "Checking if '$($extractedPath)' exists"
                    "Checking if '$($extractedPath)' exists" | Out-File -FilePath $infectedLog -Encoding ascii -Append
                    if (Test-Path -Path $extractedPath) {
                        Write-Warning "'$($extractedPath)' exists"
                        "'$($extractedPath)' exists" | Out-File -FilePath $infectedLog -Encoding ascii -Append

                        $JScount = Get-ChildItem $extractedPath -Filter "*.js"
                        if ($JScount.Count -gt 0) {
                            Write-Warning "'$($extractedPath)' contains potentially malicious Javascript file(s)! Recommend running it through Mandiant's Gootloader Decoder here: https://github.com/mandiant/gootloader or https://gootloader.zip/decode-zip-or-js.php. I also recommend scanning with antivirus software or deleting"
                            "'$($extractedPath)' contains potentially malicious Javascript file(s)! Recommend running it through Mandiant's Gootloader Decoder here: https://github.com/mandiant/gootloader or https://gootloader.zip/decode-zip-or-js.php. I also recommend scanning with antivirus software or deleting" | Out-File -FilePath $infectedLog -Encoding ascii -Append
                        }
                    }
                }
            }
        }
    }
}

& notepad "$($env:USERPROFILE)\Desktop\INFECTED_LOG.txt"; #Open the log to review

Write-Host "Press Enter to exit"
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")