rule CheshireCat_Sample2_RID2E47 : APT DEMO EXE FILE {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
      date = "2015-08-08 11:07:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "mpgvwr32.dll" fullword ascii
      $s1 = "Unexpected failure of wait! (%d)" fullword ascii
      $s2 = "\"%s\" /e%d /p%s" fullword ascii
      $s4 = "error in params!" fullword ascii
      $s5 = "sscanf" fullword ascii
      $s6 = "<>Param : 0x%x" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 4 of ( $s* )
}