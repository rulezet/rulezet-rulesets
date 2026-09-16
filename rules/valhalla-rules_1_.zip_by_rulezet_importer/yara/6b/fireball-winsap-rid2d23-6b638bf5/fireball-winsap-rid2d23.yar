rule Fireball_winsap_RID2D23 : APT DEMO EXE FILE {
   meta:
      description = "Detects Fireball malware - file winsap.dll"
      author = "Florian Roth"
      reference = "https://blog.checkpoint.com/research/fireball-chinese-malware-250-million-infection/"
      date = "2017-06-02 10:19:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "c7244d139ef9ea431a5b9cc6a2176a6a9908710892c74e215431b99cd5228359"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "aHR0cDovL2" ascii
      $s2 = "%s\\svchost.exe -k %s" fullword wide
      $s3 = "\\SETUP.dll" wide
      $s4 = "WinSAP.dll" fullword ascii
      $s5 = "Error %u in WinHttpQueryDataAvailable." fullword ascii
      $s6 = "UPDATE OVERWRITE" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 600KB and 4 of them )
}