rule Webshell_phpbackdoor15_php_RID3140 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file phpbackdoor15.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:14:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "echo \"fichier telecharge dans \".good_link(\"./\".$_FILES[\"fic\"][\"na" 
      $s2 = "if(move_uploaded_file($_FILES[\"fic\"][\"tmp_name\"],good_link(\"./\".$_FI" 
      $s3 = "echo \"Cliquez sur un nom de fichier pour lancer son telechargement. Cliquez s" 
   condition: 
      1 of them
}