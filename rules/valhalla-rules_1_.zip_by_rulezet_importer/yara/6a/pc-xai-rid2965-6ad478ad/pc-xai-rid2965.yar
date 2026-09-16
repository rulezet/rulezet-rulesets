rule Pc_xai_RID2965 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file xai.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 22:33:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Powered by CoolDiyer @ C.Rufus Security Team 05/19/2008  http://www.xcodez.com/" fullword wide
      $s2 = "%SystemRoot%\\System32\\" ascii
      $s3 = "%APPDATA%\\" ascii
      $s4 = "---- C.Rufus Security Team ----" fullword wide
      $s5 = "www.snzzkz.com" fullword wide
      $s6 = "%CommonProgramFiles%\\" ascii
      $s7 = "GetRand.dll" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and all of them
}