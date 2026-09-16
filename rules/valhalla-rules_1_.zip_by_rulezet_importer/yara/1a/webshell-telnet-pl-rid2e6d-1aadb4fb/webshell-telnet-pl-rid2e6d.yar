rule Webshell_telnet_pl_RID2E6D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file telnet.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:14:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "W A R N I N G: Private Server" 
      $s2 = "$Message = q$<pre><font color=\"#669999\"> _____  _____  _____          _____   " 
   condition: 
      all of them
}