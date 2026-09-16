rule Webshell_Tools_JSP_cmd_RID2F96 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file cmd.jSp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 12:03:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
      $s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"Conn\"" ascii
      $s2 = "<%@ page import=\"java.io.*\" %>" fullword ascii
      $s3 = "out.print(\"Hi,Man 2015<br /><!--?Confpwd=023&Conn=ls-->\");" fullword ascii
      $s4 = "while((a=in.read(b))!=-1){" fullword ascii
      $s5 = "out.println(new String(b));" fullword ascii
      $s6 = "out.print(\"</pre>\");" fullword ascii
      $s7 = "out.print(\"<pre>\");" fullword ascii
      $s8 = "int a = -1;" fullword ascii
      $s9 = "byte[] b = new byte[2048];" fullword ascii
   condition: 
      filesize < 3KB and 7 of them
}