rule HScan_v1_20_hscan_RID2D11 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file hscan.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:16:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
      $s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,100" fullword ascii
      $s3 = ".\\report\\%s-%s.html" fullword ascii
      $s4 = ".\\log\\Hscan.log" fullword ascii
      $s5 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 2 of them
}