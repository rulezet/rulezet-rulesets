rule Webshell_Rem_View_php_php_RID3112 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Rem View.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:06:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$php=\"/* line 1 */\\n\\n// \".mm(\"for example, uncomment next line\").\"" 
      $s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'" 
      $s4 = "Welcome to phpRemoteView (RemView)" 
   condition: 
      1 of them
}