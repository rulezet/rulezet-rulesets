rule Webshell_PHP_404_b_RID2D46 : DEMO SCRIPT T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 404.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:24:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "<span>Posix_getpwuid (\"Read\" /etc/passwd)" 
   condition: 
      all of them
}