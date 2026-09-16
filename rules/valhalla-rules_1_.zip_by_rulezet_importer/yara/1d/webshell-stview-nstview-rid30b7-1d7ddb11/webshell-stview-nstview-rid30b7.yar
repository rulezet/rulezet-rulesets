rule Webshell_stview_nstview_RID30B7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file nstview.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:51:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "open STDIN,\\\"<&X\\\";open STDOUT,\\\">&X\\\";open STDERR,\\\">&X\\\";exec(\\\"/bin/sh -i\\\");" 
   condition: 
      all of them
}