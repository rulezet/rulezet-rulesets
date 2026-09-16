rule CN_Honker_Alien_ee_RID2DD9 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file ee.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:49:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "GetIIS UserName and PassWord." fullword wide
      $s2 = "Read IIS ID For FreeHost." fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 50KB and all of them
}