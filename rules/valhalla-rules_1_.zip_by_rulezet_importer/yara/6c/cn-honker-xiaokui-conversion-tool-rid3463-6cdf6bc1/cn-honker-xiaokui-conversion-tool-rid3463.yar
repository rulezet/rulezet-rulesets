rule CN_Honker_Xiaokui_conversion_tool_RID3463 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Xiaokui_conversion_tool.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:28:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "update [dv_user] set usergroupid=1 where userid=2;--" fullword ascii
      $s2 = "To.exe" fullword wide
      $s3 = "by zj1244" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 240KB and 2 of them
}