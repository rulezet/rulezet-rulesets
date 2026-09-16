rule Webshell_jspShell_1_RID2E7B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file jspShell.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:16:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<input type=\"checkbox\" name=\"autoUpdate\" value=\"AutoUpdate\" on" 
      $s1 = "onblur=\"document.shell.autoUpdate.checked= this.oldValue;" 
   condition: 
      all of them
}