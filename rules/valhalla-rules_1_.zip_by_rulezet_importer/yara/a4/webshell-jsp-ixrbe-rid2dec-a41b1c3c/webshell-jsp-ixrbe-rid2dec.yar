rule Webshell_jsp_IXRbE_RID2DEC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file IXRbE.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:52:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application" 
   condition: 
      all of them
}