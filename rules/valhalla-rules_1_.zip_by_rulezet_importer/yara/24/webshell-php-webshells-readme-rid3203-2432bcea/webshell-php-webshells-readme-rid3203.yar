rule WebShell_php_webshells_README_RID3203 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file README.md"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 13:47:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Common php webshells. Do not host the file(s) in your server!" fullword
      $s1 = "php-webshells" fullword
   condition: 
      all of them
}