rule CN_Honker_mysql_injectV1_1_Creak_RID3335 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file mysql_injectV1.1_Creak.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:38:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "1http://192.169.200.200:2217/mysql_inject.php?id=1" fullword ascii
      $s12 = "OnGetPassword" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 5890KB and all of them
}