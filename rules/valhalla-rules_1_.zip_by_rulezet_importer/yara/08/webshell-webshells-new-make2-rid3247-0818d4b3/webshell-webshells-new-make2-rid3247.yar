rule Webshell_webshells_new_make2_RID3247 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file make2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:58:21"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8" 
   condition: 
      all of them
}