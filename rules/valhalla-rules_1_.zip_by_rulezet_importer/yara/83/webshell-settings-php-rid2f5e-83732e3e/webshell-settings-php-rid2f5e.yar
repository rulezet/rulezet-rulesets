rule Webshell_settings_PHP_RID2F5E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file settings.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:54:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Port: <input name=\"port\" type=\"text\" value=\"8888\">" fullword ascii
      $s2 = "<li>Reverse Shell - " fullword ascii
      $s3 = "<li><a href=\"<?php echo plugins_url('file.php', __FILE__);?>\">File Browser</a>" ascii
   condition: 
      filesize < 13KB and all of them
}