rule CN_Honker_smsniff_smsniff_RID3112 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file smsniff.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:06:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "smsniff.exe" fullword wide
      $s5 = "SmartSniff" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 267KB and all of them
}