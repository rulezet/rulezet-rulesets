rule MAL_Katz_Stealer_May25_RID2F00 : DEMO EXE FILE MAL katzstealer {
   meta:
      description = "Detects Katz stealer"
      author = "MalGamy"
      reference = "Internal Research"
      date = "2025-05-16 11:38:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL, katzstealer"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Motherboard Product: %s" ascii
      $s2 = "cmd.exe /c %s" ascii
      $s3 = "reg export \"%s\" \"%s\" /y" ascii
      $s4 = ").request({ hostname: '" ascii
      $s5 = "Type: Removable" 
      $s6 = "%s\\Microsoft\\Windows Live Mail" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 4 of them
}