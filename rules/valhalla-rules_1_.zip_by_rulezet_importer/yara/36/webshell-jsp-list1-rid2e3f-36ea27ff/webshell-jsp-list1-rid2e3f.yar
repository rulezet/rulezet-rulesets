rule Webshell_jsp_list1_RID2E3F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file list1.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:06:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "case 's':ConnectionDBM(out,encodeChange(request.getParameter(\"drive" 
      $s9 = "return \"<a href=\\\"javascript:delFile('\"+folderReplace(file)+\"')\\\"" 
   condition: 
      all of them
}