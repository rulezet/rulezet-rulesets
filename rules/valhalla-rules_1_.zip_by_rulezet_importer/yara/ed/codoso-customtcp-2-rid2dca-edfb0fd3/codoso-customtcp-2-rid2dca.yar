rule Codoso_CustomTCP_2_RID2DCA : DEMO EXE FILE G0073 MAL T1007 {
   meta:
      description = "Detects Codoso APT CustomTCP Malware"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
      date = "2016-01-30 10:46:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, G0073, MAL, T1007"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "varus_service_x86.dll" fullword ascii
      $s2 = "/s %s /p %d /st %d /rt %d" fullword ascii
      $s3 = "net start %%1" fullword ascii
      $s4 = "ping 127.1 > nul" fullword ascii
      $s5 = "McInitMISPAlertEx" fullword ascii
      $s6 = "sc start %%1" fullword ascii
      $s7 = "B_WKNDNSK^" fullword ascii
      $s8 = "net stop %%1" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 406KB and all of them
}