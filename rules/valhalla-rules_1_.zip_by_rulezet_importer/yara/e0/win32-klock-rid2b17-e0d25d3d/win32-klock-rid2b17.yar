rule Win32_klock_RID2B17 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file klock.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:51:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "klock.dll" fullword ascii
      $s2 = "Erreur : impossible de basculer le bureau ; SwitchDesktop : " fullword wide
      $s3 = "klock de mimikatz pour Windows" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 250KB and all of them
}