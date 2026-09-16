rule CN_Honker_Fckeditor_RID2E62 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Fckeditor.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:12:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "explorer.exe http://user.qzone.qq.com/568148075" fullword wide
      $s7 = "Fckeditor.exe" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1340KB and all of them
}