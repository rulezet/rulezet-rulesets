rule Webshell_ASP_CmdAsp_2_RID2EB2 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file CmdAsp.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:25:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "' -- Read the output from our command and remove the temp file -- '" 
      $s6 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" 
      $s9 = "' -- create the COM objects that we will be using -- '" 
   condition: 
      all of them
}