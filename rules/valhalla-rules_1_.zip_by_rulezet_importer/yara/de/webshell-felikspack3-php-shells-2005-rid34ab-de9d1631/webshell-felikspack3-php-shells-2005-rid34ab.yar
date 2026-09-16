rule Webshell_FeliksPack3___PHP_Shells_2005_RID34AB : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2005.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 15:40:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "window.open(\"\"&url&\"?id=edit&path=\"+sfile+\"&op=copy&attrib=\"+attrib+\"&dpath=\"+lp" 
      $s3 = "<input name=\"dbname\" type=\"hidden\" id=\"dbname\" value=\"<%=request(\"dbname\")%>\">" 
   condition: 
      all of them
}