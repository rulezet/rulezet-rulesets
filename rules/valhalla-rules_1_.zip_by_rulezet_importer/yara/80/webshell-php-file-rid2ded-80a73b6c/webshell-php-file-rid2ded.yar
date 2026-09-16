rule Webshell_php_file_RID2DED : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file file.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:52:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$allowedIPs =" fullword ascii
      $s2 = "<a href=\"<?php echo $_SERVER['PHP_SELF']  ?>\">Home</a><br/>" fullword ascii
      $s3 = "$dir  = isset($_GET[\"dir\"])  ? $_GET[\"dir\"]  : \".\";" fullword ascii
      $s4 = "$curdir .= substr($curdir, -1) != \"/\" ? \"/\" : \"\";" fullword ascii
   condition: 
      filesize < 10KB and all of them
}