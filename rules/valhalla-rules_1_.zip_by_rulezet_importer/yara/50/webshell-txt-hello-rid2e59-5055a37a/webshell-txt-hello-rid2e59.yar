rule Webshell_Txt_hello_RID2E59 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file hello.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:10:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Dim myProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
      $s1 = "myProcessStartInfo.Arguments=\"/c \" & Cmd.text" fullword ascii
      $s2 = "myProcess.Start()" fullword ascii
      $s3 = "<p align=\"center\"><a href=\"?action=cmd\" target=\"_blank\">" fullword ascii
   condition: 
      filesize < 25KB and all of them
}