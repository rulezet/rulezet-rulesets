rule Webshell_jsp_tree_RID2E02 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file tree.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:56:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "$('#tt2').tree('options').url = \"selectChild.action?checki" 
      $s6 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+requ" 
   condition: 
      all of them
}