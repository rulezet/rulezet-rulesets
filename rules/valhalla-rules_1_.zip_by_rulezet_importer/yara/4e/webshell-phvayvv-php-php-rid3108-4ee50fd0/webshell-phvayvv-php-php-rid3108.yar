rule Webshell_phvayvv_php_php_RID3108 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file phvayvv.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:05:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "{mkdir(\"$dizin/$duzenx2\",777)" 
      $s1 = "$baglan=fopen($duzkaydet,'w');" 
      $s2 = "PHVayv 1.0" 
   condition: 
      1 of them
}