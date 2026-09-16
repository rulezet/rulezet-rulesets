rule _hscan_hscan_hscangui_RID2F9A : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - from files hscan.exe, hscan.exe, hscangui.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 12:04:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
      hash2 = "af8aced0a78e1181f4c307c78402481a589f8d07"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".\\log\\Hscan.log" fullword ascii
      $s2 = ".\\report\\%s-%s.html" fullword ascii
      $s3 = "[%s]: checking \"FTP account: ftp/ftp@ftp.net\" ..." fullword ascii
      $s4 = "[%s]: IPC NULL session connection success !!!" fullword ascii
      $s5 = "Scan %d targets,use %4.1f minutes" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 240KB and all of them
}