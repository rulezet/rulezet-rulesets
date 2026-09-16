rule CN_Honker_Master_beta_1_7_RID3054 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Master_beta_1.7.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:35:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "http://seo.chinaz.com/?host=" fullword ascii
      $s2 = "Location: getpass.asp?info=" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 312KB and all of them
}