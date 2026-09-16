rule Webshell_Safe_mode_breaker_RID3164 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Safe mode breaker.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:20:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "preg_match(\"/SAFE\\ MODE\\ Restriction\\ in\\ effect\\..*whose\\ uid\\ is(" 
      $s6 = "$path =\"{$root}\".((substr($root,-1)!=\"/\") ? \"/\" : NULL)." 
   condition: 
      1 of them
}