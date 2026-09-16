rule Webshell_cmd_asp_5_1_asp_RID3044 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file cmd-asp-5.1.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:32:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Call oS.Run(\"win.com cmd.exe /c del \"& szTF,0,True)" fullword
      $s3 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
   condition: 
      1 of them
}