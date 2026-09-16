rule Webshell_customize_RID2E89 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file customize.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:18:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z" 
   condition: 
      all of them
}