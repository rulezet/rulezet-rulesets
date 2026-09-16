rule WebShell_JspWebshell_1_2_2_RID309B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file JspWebshell 1.2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:47:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
      $s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java." 
      $s4 = "// String tempfilepath=request.getParameter(\"filepath\");" fullword
      $s15 = "endPoint=random1.getFilePointer();" fullword
      $s20 = "if (request.getParameter(\"command\") != null) {" fullword
   condition: 
      3 of them
}