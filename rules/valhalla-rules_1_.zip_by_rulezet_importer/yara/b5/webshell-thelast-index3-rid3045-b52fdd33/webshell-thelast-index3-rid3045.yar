rule Webshell_thelast_index3_RID3045 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file index3.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:32:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"Your Name\\\" field is r" 
   condition: 
      all of them
}