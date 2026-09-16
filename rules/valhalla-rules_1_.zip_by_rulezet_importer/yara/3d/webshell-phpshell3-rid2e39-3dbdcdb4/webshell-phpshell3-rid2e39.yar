rule Webshell_phpshell3_RID2E39 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file phpshell3.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:05:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "<input name=\"nounce\" type=\"hidden\" value=\"<?php echo $_SESSION['nounce'];" 
      $s5 = "<p>Username: <input name=\"username\" type=\"text\" value=\"<?php echo $userna" 
      $s7 = "$_SESSION['output'] .= \"cd: could not change to: $new_dir\\n\";" fullword
   condition: 
      2 of them
}