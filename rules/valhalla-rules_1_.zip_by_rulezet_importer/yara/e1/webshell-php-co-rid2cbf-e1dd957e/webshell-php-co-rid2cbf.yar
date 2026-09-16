rule Webshell_PHP_co_RID2CBF : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file co.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:02:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "cGX6R9q733WvRRjISKHOp9neT7wa6ZAD8uthmVJV" fullword
      $s11 = "6Mk36lz/HOkFfoXX87MpPhZzBQH6OaYukNg1OE1j" fullword
   condition: 
      all of them
}