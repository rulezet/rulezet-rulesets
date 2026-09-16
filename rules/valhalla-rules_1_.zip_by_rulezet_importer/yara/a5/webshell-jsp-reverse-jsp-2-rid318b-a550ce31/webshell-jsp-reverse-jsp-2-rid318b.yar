rule Webshell_jsp_reverse_jsp_2_RID318B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file jsp-reverse.jsp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:27:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "// backdoor.jsp" 
      $s1 = "JSP Backdoor Reverse Shell" 
      $s2 = "http://michaeldaw.org" 
   condition: 
      2 of them
}