rule Webshell_FSO_s_RemExp_2_RID2FA1 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file RemExp.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:05:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = " Then Response.Write \"" 
      $s3 = "<a href= \"<%=Request.ServerVariables(\"script_name\")%>" 
   condition: 
      all of them
}