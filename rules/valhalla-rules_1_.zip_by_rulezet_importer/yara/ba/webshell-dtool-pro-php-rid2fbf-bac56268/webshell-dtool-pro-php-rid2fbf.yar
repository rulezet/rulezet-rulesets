rule Webshell_DTool_Pro_php_RID2FBF : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file DTool Pro.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:10:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "r3v3ng4ns\\nDigite" 
      $s1 = "if(!@opendir($chdir)) $ch_msg=\"dtool: line 1: chdir: It seems that the permissi" 
      $s3 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n" 
   condition: 
      1 of them
}