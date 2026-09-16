rule WebShell_php_webshells_lolipop_RID3354 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file lolipop.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:43:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "$commander = $_POST['commander']; " fullword
      $s9 = "$sourcego = $_POST['sourcego']; " fullword
      $s20 = "$result = mysql_query($loli12) or die (mysql_error()); " fullword
   condition: 
      all of them
}