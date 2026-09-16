rule Webshell_remview_2003_04_22_RID304F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file remview_2003_04_22.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:34:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\"<b>\".mm(\"Eval PHP code\").\"</b> (\".mm(\"don't type\").\" \\\"&lt;?\\\"" 
   condition: 
      all of them
}