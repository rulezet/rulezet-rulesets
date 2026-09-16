rule Codoso_PGV_PVID_6_RID2CEB : DEMO EXE FILE G0073 MAL T1218_011 {
   meta:
      description = "Detects Codoso APT PGV_PVID Malware"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
      date = "2016-01-30 10:09:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, G0073, MAL, T1218_011"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "rundll32 \"%s\",%s" fullword ascii
      $s1 = "/c ping 127.%d & del \"%s\"" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 6000KB and all of them
}