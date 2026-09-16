rule x64_klock_RID2A66 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file klock.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 05:41:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Bienvenue dans un processus distant" fullword wide
      $s2 = "klock.dll" fullword ascii
      $s3 = "Erreur : le bureau courant (" wide
      $s4 = "klock de mimikatz pour Windows" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 907KB and all of them
}