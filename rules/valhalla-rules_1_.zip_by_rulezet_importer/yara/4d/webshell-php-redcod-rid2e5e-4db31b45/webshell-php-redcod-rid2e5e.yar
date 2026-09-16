rule Webshell_PHP_redcod_RID2E5E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file redcod.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:11:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "H8p0bGFOEy7eAly4h4E4o88LTSVHoAglJ2KLQhUw" fullword
      $s1 = "HKP7dVyCf8cgnWFy8ocjrP5ffzkn9ODroM0/raHm" fullword
   condition: 
      all of them
}