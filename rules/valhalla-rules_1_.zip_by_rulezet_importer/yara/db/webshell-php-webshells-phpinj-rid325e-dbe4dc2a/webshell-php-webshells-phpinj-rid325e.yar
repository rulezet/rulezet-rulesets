rule WebShell_php_webshells_pHpINJ_RID325E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file pHpINJ.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:02:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';" fullword
      $s10 = "<form action = \"<?php echo \"$_SERVER[PHP_SELF]\" ; ?>\" method = \"post\">" fullword
      $s11 = "$sql = \"0' UNION SELECT '0' , '<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 IN" 
      $s13 = "Full server path to a writable file which will contain the Php Shell <br />" fullword
      $s14 = "$expurl= $url.\"?id=\".$sql ;" fullword
      $s15 = "<header>||   .::News PHP Shell Injection::.   ||</header> <br /> <br />" fullword
      $s16 = "<input type = \"submit\" value = \"Create Exploit\"> <br /> <br />" fullword
   condition: 
      1 of them
}