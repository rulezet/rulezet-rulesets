rule Webshell_asp_shell_2_RID2EF2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file shell.asp"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:36:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<form action=\"shell.asp\" method=\"POST\" name=\"shell\">" fullword ascii
      $s2 = "%ComSpec% /c dir" fullword ascii
      $s3 = "Set objCmd = wShell.Exec(cmd)" fullword ascii
      $s4 = "Server.ScriptTimeout = 180" fullword ascii
      $s5 = "cmd = Request.Form(\"cmd\")" fullword ascii
      $s6 = "' ***  http://laudanum.secureideas.net" fullword ascii
      $s7 = "Dim wshell, intReturn, strPResult" fullword ascii
   condition: 
      filesize < 15KB and 4 of them
}