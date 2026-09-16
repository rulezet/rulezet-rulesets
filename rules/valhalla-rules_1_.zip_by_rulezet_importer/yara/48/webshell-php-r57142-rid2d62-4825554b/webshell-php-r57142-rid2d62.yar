rule Webshell_PHP_r57142_RID2D62 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file r57142.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:29:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');" fullword
   condition: 
      all of them
}