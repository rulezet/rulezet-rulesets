rule Webshell_phpshell_2_1_config_RID31FC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file config.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:45:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "; (choose good passwords!).  Add uses as simple 'username = \"password\"' lines." fullword
   condition: 
      all of them
}