rule Codoso_Gh0st_2_RID2C2E : DEMO EXE FILE G0073 MAL T1218_011 {
   meta:
      description = "Detects Codoso APT Gh0st Malware"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
      date = "2016-01-30 09:38:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, G0073, MAL, T1218_011"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "cmd.exe /c ping 127.0.0.1 && ping 127.0.0.1 && sc start %s && ping 127.0.0.1 && sc start %s" fullword ascii
      $s1 = "rundll32.exe \"%s\", RunMeByDLL32" fullword ascii
      $s13 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
      $s14 = "%s -r debug 1" fullword ascii
      $s15 = "\\\\.\\keymmdrv1" fullword ascii
      $s17 = "RunMeByDLL32" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and 1 of them
}