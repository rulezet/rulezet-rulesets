rule x_way2_5_X_way_RID2C66 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file X-way.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:47:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "TTFTPSERVERFRM" fullword wide
      $s1 = "TPORTSCANSETFRM" fullword wide
      $s2 = "TIISSHELLFRM" fullword wide
      $s3 = "TADVSCANSETFRM" fullword wide
      $s4 = "ntwdblib.dll" fullword ascii
      $s5 = "TSNIFFERFRM" fullword wide
      $s6 = "TCRACKSETFRM" fullword wide
      $s7 = "TCRACKFRM" fullword wide
      $s8 = "dbnextrow" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 5 of them
}