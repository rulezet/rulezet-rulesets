rule hscan_gui_RID2AC2 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file hscan-gui.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:15:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Hscan.EXE" fullword wide
      $s1 = "RestTool.EXE" fullword ascii
      $s3 = "Hscan Application " fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 550KB and all of them
}