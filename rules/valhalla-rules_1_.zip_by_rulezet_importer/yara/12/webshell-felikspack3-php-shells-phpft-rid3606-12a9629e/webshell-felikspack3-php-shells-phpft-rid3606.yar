rule Webshell_FeliksPack3___PHP_Shells_phpft_RID3606 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phpft.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 16:38:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "PHP Files Thief" 
      $s11 = "http://www.4ngel.net" 
   condition: 
      all of them
}