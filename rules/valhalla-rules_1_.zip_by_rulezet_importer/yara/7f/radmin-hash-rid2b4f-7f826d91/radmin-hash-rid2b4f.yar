rule Radmin_Hash_RID2B4F : CHINA DEMO EXE FILE HKTL remoteadmin {
   meta:
      description = "Chinese Hacktool Set - file Radmin_Hash_RID2B4F.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:01:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, remoteadmin"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<description>IEBars</description>" fullword ascii
      $s2 = "PECompact2" fullword ascii
      $s3 = "Radmin, Remote Administrator" fullword wide
      $s4 = "Radmin 3.0 Hash " fullword wide
      $s5 = "HASH1.0" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and all of them
}