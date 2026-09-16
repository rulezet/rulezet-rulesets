rule Webshell_CmdAsp_asp_RID2E81 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file CmdAsp.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:17:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "CmdAsp.asp" 
      $s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
      $s2 = "-- Use a poor man's pipe ... a temp file --" 
      $s3 = "maceo @ dogmile.com" 
   condition: 
      2 of them
}