rule Webshell_php_404_a_RID2DA5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 404.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:40:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$pass = md5(md5(md5($pass)));" fullword
   condition: 
      all of them
}