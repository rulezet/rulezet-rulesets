rule Webshell_lamashell_php_RID3000 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file lamashell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:21:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "lama's'hell" fullword
      $s1 = "if($_POST['king'] == \"\") {" 
      $s2 = "if (move_uploaded_file($_FILES['fila']['tmp_name'], $curdir.\"/\".$_FILES['f" 
   condition: 
      1 of them
}