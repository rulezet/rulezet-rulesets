rule Webshell_phpspy_2005_full_RID3082 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phpspy_2005_full.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:42:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "echo \"  <td align=\\\"center\\\" nowrap valign=\\\"top\\\"><a href=\\\"?downfile=\".urlenco" 
   condition: 
      all of them
}