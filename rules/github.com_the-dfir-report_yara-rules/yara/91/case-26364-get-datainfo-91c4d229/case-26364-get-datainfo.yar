rule case_26364_Get_DataInfo {
   meta:
      description = "Case 26364 - file Get-DataInfo.ps1"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/08/26/blacksuit-ransomware/"
      date = "2024-08-20"
      hash1 = "6f5f3c8aa308819337a2f69d453ab2f6252491aa0ccc94a8364d0c3c10533173"
   strings:
      $x1 = "$computername = Get-Content \".\\result\\livePCs.txt\" -ReadCount 0" fullword ascii
      $x2 = "$computername = Get-Content \".\\result\\livePCs.txt\" -ReadCount 0  " fullword ascii
      $s3 = "'disk' {Test-LHosts; Get-Diskinfo | Export-Csv -Path .\\result\\Disk.csv -NoTypeInformation; Compress-Result}" fullword ascii
      $s4 = "'all' {Test-LHosts; Get-Diskinfo | Export-Csv -Path .\\result\\Disk.csv -NoTypeInformation; Get-Software; Compress-Result}" fullword ascii
      $s5 = "default {Test-LHosts; Get-Diskinfo | Export-Csv -Path .\\result\\Disk.csv -NoTypeInformation; Get-Software; Compress-Result}" fullword ascii
      $s6 = "'nocompress' {Test-LHosts; Get-Diskinfo | Export-Csv -Path .\\result\\Disk.csv -NoTypeInformation; Get-Software}" fullword ascii
      $s7 = "}else{Add-Content \"$computer is not reachable\" -path .\\result\\error.txt}" fullword ascii
      $s8 = "$testcomputers = Get-Content -Path $compsfile -ReadCount 0" fullword ascii
      $s9 = "'noping' {Get-Diskinfo | Export-Csv -Path .\\result\\Disk.csv -NoTypeInformation; Get-Software; Compress-Result}" fullword ascii
      $s10 = "Try{Get-WmiObject Win32_LogicalDisk -filter \"DriveType=3\" -computer $computer | Select SystemName,DeviceID,@{Name=\"Size(GB)\"" ascii
      $s11 = "Add-Content -value $computer -path .\\result\\livePCs.txt" fullword ascii
      $s12 = "Add-Content -value $computer -path .\\result\\deadPCs.txt" fullword ascii
      $s13 = "Invoke-Expression \"& '.\\7z.exe' a '$typearchiv' '$destination' '$CompressionLevel' -aoa '$Source'\"" fullword ascii
      $s14 = "Catch {Add-Content \"$computer is not reachable\" -path .\\result\\error.txt}" fullword ascii
      $s15 = "write-host -foregroundcolor cyan \"Testing Connection complete\"" fullword ascii
      $s16 = "Try{Get-WmiObject Win32_LogicalDisk -filter \"DriveType=3\" -computer $computer | Select SystemName,DeviceID,@{Name=\"Size(GB)\"" ascii
      $s17 = "Write-Progress  \"Testing Connections\" -PercentComplete $testcomputer_progress -Status \"Percent Complete - $testcomputer_progr" ascii
      $s18 = "Write-Progress  \"Testing Connections\" -PercentComplete $testcomputer_progress -Status \"Percent Complete - $testcomputer_prog" fullword ascii
      $s19 = "'soft' {Test-LHosts; Get-Software; Compress-Result}" fullword ascii
      $s20 = "}Catch{Add-Content \"$registry\" -path .\\result\\error.txt}" fullword ascii
   condition:
      uint16(0) == 0x5323 and filesize < 20KB and
      1 of ($x*) and 4 of them
}