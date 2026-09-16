rule Webshell_php_backdoor_RID2F92 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file php-backdoor.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:02:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fname))" fullword
      $s2 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input " 
   condition: 
      all of them
}