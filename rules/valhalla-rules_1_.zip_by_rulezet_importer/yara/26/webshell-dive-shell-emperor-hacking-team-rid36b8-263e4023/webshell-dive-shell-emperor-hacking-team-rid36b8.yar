rule Webshell_Dive_Shell_Emperor_Hacking_Team_RID36B8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files Dive Shell 1.0 - Emperor Hacking Team.php, phpshell.php, SimShell 1.0 - Simorgh Security MGZ.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 17:07:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f8a6d5306fb37414c5c772315a27832f"
      hash2 = "37cb1db26b1b0161a4bf678a6b4565bd"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if (($i = array_search($_REQUEST['command'], $_SESSION['history'])) !== fals" 
      $s9 = "if (ereg('^[[:blank:]]*cd[[:blank:]]*$', $_REQUEST['command'])) {" fullword
   condition: 
      all of them
}