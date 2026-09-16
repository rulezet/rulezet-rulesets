rule CN_Honker_Baidu_Extractor_Ver1_0_RID3313 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Baidu_Extractor_Ver1.0.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:32:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "\\Users\\Admin" wide
      $s11 = "soso.com" fullword wide
      $s12 = "baidu.com" fullword wide
      $s19 = "cmd /c ping " fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and all of them
}