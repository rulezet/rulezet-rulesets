rule Webshell_cpg_143_incl_xpl_RID308F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cpg_143_incl_xpl.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:45:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "$data=\"username=\".urlencode($USER).\"&password=\".urlencode($PA" 
      $s5 = "fputs($sun_tzu,\"<?php echo \\\"Hi Master!\\\";ini_set(\\\"max_execution_time" 
   condition: 
      1 of them
}