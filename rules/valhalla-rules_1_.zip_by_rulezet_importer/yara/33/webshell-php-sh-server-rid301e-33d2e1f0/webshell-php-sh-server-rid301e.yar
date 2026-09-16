rule Webshell_php_sh_server_RID301E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file server.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:26:11"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "eval(getenv('HTTP_CODE'));" fullword
   condition: 
      all of them
}