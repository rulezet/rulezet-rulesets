rule DTools2_02_DTools_RID2D0D : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file DTools.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:15:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "kernel32.dll" ascii
      $s1 = "TSETPASSWORDFORM" fullword wide
      $s2 = "TGETNTUSERNAMEFORM" fullword wide
      $s3 = "TPORTFORM" fullword wide
      $s4 = "ShellFold" fullword ascii
      $s5 = "DefaultPHotLigh" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them
}