rule hscangui_RID2A63 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file hscangui_RID2A63.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 05:36:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
      $s2 = "http://www.cnhonker.com" fullword ascii
      $s3 = "%s@ftpscan#Cracked account:  %s/%s" fullword ascii
      $s4 = "[%s]: Found \"FTP account: %s/%s\" !!!" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 220KB and 2 of them
}