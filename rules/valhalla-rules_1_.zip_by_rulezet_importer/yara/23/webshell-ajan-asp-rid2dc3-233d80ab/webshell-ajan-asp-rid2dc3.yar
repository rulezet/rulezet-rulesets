rule Webshell_Ajan_asp_RID2DC3 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Ajan.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 10:45:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "c:\\downloaded.zip" 
      $s2 = "Set entrika = entrika.CreateTextFile(\"c:\\net.vbs\", True)" fullword
      $s3 = "http://www35.websamba.com/cybervurgun/" 
   condition: 
      1 of them
}