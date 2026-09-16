rule Webshell_sig_238_cmd_2_RID2F09 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file cmd.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 11:40:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Process child = Runtime.getRuntime().exec(" ascii
      $s1 = "InputStream in = child.getInputStream();" fullword ascii
      $s2 = "String cmd = request.getParameter(\"" ascii
      $s3 = "while ((c = in.read()) != -1) {" fullword ascii
      $s4 = "<%@ page import=\"java.io.*\" %>" fullword ascii
   condition: 
      all of them
}