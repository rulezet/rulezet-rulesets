rule Webshell_s72_Shell_v1_1_Coding_RID3222 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file s72 Shell v1.1 Coding.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:52:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#800080\">Buradan Dosya " 
   condition: 
      all of them
}