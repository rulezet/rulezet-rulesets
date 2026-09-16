rule Webshell_Ajax_PHP_Command_Shell_php_RID348D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Ajax_PHP Command Shell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:35:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "newhtml = '<b>File browser is under construction! Use at your own risk!</b> <br>" 
      $s2 = "Empty Command..type \\\"shellhelp\\\" for some ehh...help" 
      $s3 = "newhtml = '<font size=0><b>This will reload the page... :(</b><br><br><form enct" 
   condition: 
      1 of them
}