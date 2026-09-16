rule Simple_PHP_BackDooR_RID2E06 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file Simple_PHP_BackDooR_RID2E06.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:56:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<hr>to browse go to http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=[directory he" 
      $s6 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fn" 
      $s9 = "// a simple php backdoor" 
   condition: 
      1 of them
}