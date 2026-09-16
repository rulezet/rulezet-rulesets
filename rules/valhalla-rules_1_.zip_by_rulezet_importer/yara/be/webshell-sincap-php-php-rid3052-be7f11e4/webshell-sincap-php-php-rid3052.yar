rule Webshell_Sincap_php_php_RID3052 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Sincap.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:34:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$baglan=fopen(\"/tmp/$ekinci\",'r');" 
      $s2 = "$tampon4=$tampon3-1" 
      $s3 = "@aventgrup.net" 
   condition: 
      2 of them
}