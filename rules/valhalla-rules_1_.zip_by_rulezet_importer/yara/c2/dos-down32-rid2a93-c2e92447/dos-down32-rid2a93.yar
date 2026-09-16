rule Dos_Down32_RID2A93 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file Down32.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 06:56:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
      $s6 = "down.exe" fullword wide
      $s15 = "get_Form1" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 137KB and all of them
}