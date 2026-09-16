rule WEBSHELL_ChinaChopper_Generic_Mar15_RID337B : CHINA DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "Detects China Chopper webshells"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf"
      date = "2015-03-10 14:49:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-12-14"
      tags = "CHINA, DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x_aspx = /%@\sPage\sLanguage=.Jscript.%><%eval\(Request\.Item\[.{,100}unsafe/ 
      $x_php = /<?php.\@eval\(\$_POST./ 
      $fp1 = "GET /" 
      $fp2 = "POST /" 
   condition: 
      filesize < 300KB and 1 of ( $x* ) and not 1 of ( $fp* )
}