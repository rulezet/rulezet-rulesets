rule Webshell_ELMALISEKER_Backd00r_RID30DA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ELMALISEKER Backd00r.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:57:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "response.write(\"<tr><td bgcolor=#F8F8FF><input type=submit name=cmdtxtFileOptio" 
      $s2 = "if FP = \"RefreshFolder\" or request.form(\"cmdOption\")=\"DeleteFolder\" or req" 
   condition: 
      all of them
}