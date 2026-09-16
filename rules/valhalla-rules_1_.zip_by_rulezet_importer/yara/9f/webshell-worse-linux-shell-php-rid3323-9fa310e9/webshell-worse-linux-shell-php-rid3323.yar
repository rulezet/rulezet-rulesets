rule Webshell_Worse_Linux_Shell_php_RID3323 : DEMO LINUX SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Worse Linux Shell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:35:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, LINUX, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "print \"<tr><td><b>Server is:</b></td><td>\".$_SERVER['SERVER_SIGNATURE'].\"</td" 
      $s2 = "print \"<tr><td><b>Execute command:</b></td><td><input size=100 name=\\\"_cmd" 
   condition: 
      1 of them
}