rule Webshell_asp_list_RID2E05 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file list.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:56:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">" fullword
      $s4 = "Response.Write(\"<h3>FILE: \" & file & \"</h3>\")" fullword
   condition: 
      all of them
}