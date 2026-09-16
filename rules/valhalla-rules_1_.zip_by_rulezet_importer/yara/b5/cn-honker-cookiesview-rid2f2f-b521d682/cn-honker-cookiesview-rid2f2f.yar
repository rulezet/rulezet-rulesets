rule CN_Honker_CookiesView_RID2F2F : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file CookiesView.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:46:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "V1.0  Http://www.darkst.com Code:New4" fullword ascii
      $s1 = "maotpo@126.com" fullword ascii
      $s2 = "www.baidu.com" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 640KB and all of them
}