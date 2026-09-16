rule Webshell_jsp_asd_RID2D8A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file asd.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:36:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%>" fullword
      $s6 = "<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url" 
   condition: 
      all of them
}