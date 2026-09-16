rule WebShell_JspWebshell_1_2_RID300A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file JspWebshell_1.2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:22:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
      $s1 = "String password=request.getParameter(\"password\");" fullword
      $s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java." 
      $s7 = "String editfile=request.getParameter(\"editfile\");" fullword
      $s8 = "//String tempfilename=request.getParameter(\"file\");" fullword
      $s12 = "password = (String)session.getAttribute(\"password\");" fullword
   condition: 
      3 of them
}