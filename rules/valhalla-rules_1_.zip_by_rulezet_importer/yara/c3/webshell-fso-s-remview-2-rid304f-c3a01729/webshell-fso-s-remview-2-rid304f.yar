rule Webshell_FSO_s_remview_2_RID304F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file remview.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:34:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<xmp>$out</" 
      $s1 = ".mm(\"Eval PHP code\")." 
   condition: 
      all of them
}