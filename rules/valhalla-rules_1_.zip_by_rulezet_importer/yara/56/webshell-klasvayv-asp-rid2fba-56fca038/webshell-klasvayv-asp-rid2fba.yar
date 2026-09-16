rule Webshell_klasvayv_asp_RID2FBA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file klasvayv.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:09:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "set aktifklas=request.querystring(\"aktifklas\")" 
      $s2 = "action=\"klasvayv.asp?klasorac=1&aktifklas=<%=aktifklas%>&klas=<%=aktifklas%>" 
      $s3 = "<font color=\"#858585\">www.aventgrup.net" 
      $s4 = "style=\"BACKGROUND-COLOR: #95B4CC; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT" 
   condition: 
      1 of them
}