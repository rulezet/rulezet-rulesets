rule CN_Honker_Cracker_SHELL_RID2F59 : CHINA DEMO EXE FILE HKTL SCRIPT {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file SHELL.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:53:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "http://127.0.0.1/error1.asp" fullword ascii
      $s2 = "password,PASSWORD,pass,PASS,Lpass,lpass,Password" fullword wide
      $s3 = "\\SHELL" wide
      $s4 = "WebBrowser1" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them
}