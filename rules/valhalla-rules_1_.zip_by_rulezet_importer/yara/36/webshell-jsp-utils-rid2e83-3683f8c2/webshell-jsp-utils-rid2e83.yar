rule Webshell_jsp_utils_RID2E83 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file utils.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:17:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword
      $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z" 
   condition: 
      all of them
}