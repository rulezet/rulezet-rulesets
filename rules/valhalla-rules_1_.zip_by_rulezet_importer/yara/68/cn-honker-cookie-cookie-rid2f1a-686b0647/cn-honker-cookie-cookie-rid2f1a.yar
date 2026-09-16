rule CN_Honker_COOKIE_CooKie_RID2F1A : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file CooKie.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:42:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "-1 union select 1,username,password,4,5,6,7,8,9,10 from admin" fullword ascii
      $s5 = "CooKie.exe" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 360KB and all of them
}