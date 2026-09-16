rule Webshell_php_killnc_RID2ECA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file killnc.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:29:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii
      $s2 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
      $s3 = "<?php echo exec('killall nc');?>" fullword ascii
      $s4 = "<title>Laudanum Kill nc</title>" fullword ascii
      $s5 = "foreach ($allowedIPs as $IP) {" fullword ascii
   condition: 
      filesize < 15KB and 4 of them
}