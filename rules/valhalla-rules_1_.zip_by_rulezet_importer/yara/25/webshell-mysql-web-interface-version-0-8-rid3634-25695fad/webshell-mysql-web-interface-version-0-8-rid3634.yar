rule Webshell_MySQL_Web_Interface_Version_0_8_RID3634 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file MySQL Web Interface Version 0.8.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 16:45:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "href='$PHP_SELF?action=dumpTable&dbname=$dbname&tablename=$tablename'>Dump</a>" 
   condition: 
      all of them
}