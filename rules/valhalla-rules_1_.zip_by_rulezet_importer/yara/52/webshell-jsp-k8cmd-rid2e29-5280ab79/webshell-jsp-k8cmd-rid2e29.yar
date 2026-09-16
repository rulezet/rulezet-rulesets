rule Webshell_jsp_k8cmd_RID2E29 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file k8cmd.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:02:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))" fullword
   condition: 
      all of them
}