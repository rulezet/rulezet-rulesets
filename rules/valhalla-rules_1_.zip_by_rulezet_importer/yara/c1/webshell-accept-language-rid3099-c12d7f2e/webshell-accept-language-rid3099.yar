rule WebShell_accept_language_RID3099 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file accept_language.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php passthru(getenv(\"HTTP_ACCEPT_LANGUAGE\")); echo '<br> by q1w2e3r4'; ?>" fullword
   condition: 
      all of them
}