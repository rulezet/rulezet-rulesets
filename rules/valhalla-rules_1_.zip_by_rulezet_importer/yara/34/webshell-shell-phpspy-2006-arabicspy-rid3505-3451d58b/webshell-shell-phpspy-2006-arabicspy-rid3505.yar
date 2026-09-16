rule Webshell_shell_phpspy_2006_arabicspy_RID3505 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:55:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "40a1f840111996ff7200d18968e42cfe"
      hash2 = "e0202adff532b28ef1ba206cf95962f2"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "elseif(($regwrite) AND !empty($_POST['writeregname']) AND !empty($_POST['regtype" 
      $s8 = "echo \"<form action=\\\"?action=shell&dir=\".urlencode($dir).\"\\\" method=\\\"P" 
   condition: 
      all of them
}