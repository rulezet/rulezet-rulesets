rule ChineseHack_Tool_RID2D44 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file CookieTools.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:24:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-20"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "http://210.73.64.88/doorway/cgi-bin/getclientip.asp?IP=" fullword ascii
      $s2 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
      $s3 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
      $s4 = "OnGetPasswordP" fullword ascii
      $s5 = "http://www.chinesehack.org/" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 5000KB and 4 of them
}