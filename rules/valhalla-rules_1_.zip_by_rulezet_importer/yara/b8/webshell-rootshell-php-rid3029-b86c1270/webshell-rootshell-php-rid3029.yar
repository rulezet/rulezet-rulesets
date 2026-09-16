rule Webshell_rootshell_php_RID3029 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file rootshell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:28:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "shells.dl.am" 
      $s1 = "This server has been infected by $owner" 
      $s2 = "<input type=\"submit\" value=\"Include!\" name=\"inc\"></p>" 
      $s4 = "Could not write to file! (Maybe you didn't enter any text?)" 
   condition: 
      2 of them
}