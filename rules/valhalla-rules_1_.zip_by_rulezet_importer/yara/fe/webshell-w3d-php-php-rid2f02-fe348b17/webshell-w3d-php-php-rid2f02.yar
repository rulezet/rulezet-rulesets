rule Webshell_w3d_php_php_RID2F02 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file w3d.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:38:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "W3D Shell" 
      $s1 = "By: Warpboy" 
      $s2 = "No Query Executed" 
   condition: 
      2 of them
}