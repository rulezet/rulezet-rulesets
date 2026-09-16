rule CN_Honker_safe3wvs_cgiscan_RID3130 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file cgiscan.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:11:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "httpclient.exe" fullword wide
      $s3 = "www.safe3.com.cn" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 357KB and all of them
}