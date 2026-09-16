rule kappfree_RID2A5F : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file kappfree_RID2A5F.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 05:30:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Bienvenue dans un processus distant" fullword wide
      $s2 = "kappfree_RID2A5F.dll" fullword ascii
      $s3 = "kappfree_RID2A5F de mimikatz pour Windows (anti AppLocker)" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them
}