rule Webshell_KA_uShell_RID2DFE : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file KA_uShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:55:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass" 
      $s6 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" 
   condition: 
      all of them
}