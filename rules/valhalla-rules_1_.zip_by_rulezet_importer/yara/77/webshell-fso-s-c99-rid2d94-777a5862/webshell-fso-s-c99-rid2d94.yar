rule Webshell_FSO_s_c99_RID2D94 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file c99.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:37:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "\"txt\",\"conf\",\"bat\",\"sh\",\"js\",\"bak\",\"doc\",\"log\",\"sfc\",\"cfg\",\"htacce" 
   condition: 
      all of them
}