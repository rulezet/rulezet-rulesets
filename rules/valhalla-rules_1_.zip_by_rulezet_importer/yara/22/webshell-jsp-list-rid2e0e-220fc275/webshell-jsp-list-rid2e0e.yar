rule Webshell_jsp_list_RID2E0E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file list.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:58:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
      $s2 = "out.print(\") <A Style='Color: \" + fcolor.toString() + \";' HRef='?file=\" + fn" 
      $s7 = "if(flist[i].canRead() == true) out.print(\"r\" ); else out.print(\"-\");" fullword
   condition: 
      all of them
}