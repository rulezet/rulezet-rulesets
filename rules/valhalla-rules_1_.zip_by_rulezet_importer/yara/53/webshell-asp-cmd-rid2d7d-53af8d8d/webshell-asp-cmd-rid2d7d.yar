rule Webshell_asp_cmd_RID2D7D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmd.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:34:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
      $s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
      $s3 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
   condition: 
      1 of them
}