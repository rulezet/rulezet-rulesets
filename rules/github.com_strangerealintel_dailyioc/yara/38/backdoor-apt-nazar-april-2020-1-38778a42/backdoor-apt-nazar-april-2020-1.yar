rule Backdoor_APT_Nazar_April_2020_1 {
   meta:
      description = "Detect strings used by APT Nazar"
      author = "Arkbird_SOLG"
      reference = "Internal research"
      date = "2020-04-29"
      modified = "2023-11-22"
      hash1 = "2fe9b76496a9480273357b6d35c012809bfa3ae8976813a7f5f4959402e3fbb6"
   strings:
      $s1 = "101;0000;" fullword ascii       $s2 = "hodll.dll" fullword ascii        $s3 = { 70 73 73 64 6B ?? ?? 2E 73 79 73 }       $s4 = { 70 73 73 64 6B ?? ?? 2E 76 78 64 }       $s5 = "##$$%%&&''(())**++,,--..//0123456789:;<=>?" fullword ascii       $s6 = "SYSTEM\\CurrentControlSet\\Services\\VxD\\MSTCP" fullword ascii        $s7 = "removehook" fullword ascii       $s8 = "installhook" fullword ascii       $s9 = "_crt_debugger_hook" fullword ascii       $s10 = "\\Files.txt" fullword ascii       $s11 = "\\report.txt" fullword ascii       $s12 = "\\Programs.txt" fullword ascii       $s13 = "\\Devices.txt" fullword ascii       $s14 = "\\music.mp3" fullword ascii       $s15 = "\\z.png" fullword ascii    condition:
     12 of them and filesize > 120KB 
}