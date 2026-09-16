rule Webshell_jspshall_jsp_RID2FB3 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file jspshall.jsp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:08:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "kj021320" 
      $s1 = "case 'T':systemTools(out);break;" 
      $s2 = "out.println(\"<tr><td>\"+ico(50)+f[i].getName()+\"</td><td> file" 
   condition: 
      2 of them
}