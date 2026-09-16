rule kappfree_2_RID2AF0 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file kappfree.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:31:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "kappfree.dll" fullword ascii
      $s2 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
      $s3 = "' introuvable !" fullword wide
      $s4 = "kiwi\\mimikatz" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 2 of them
}