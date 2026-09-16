rule Webshell_PH_Vayv_PH_Vayv_RID303F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file PH Vayv.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:31:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px in" 
      $s4 = "<font color=\"#858585\">SHOPEN</font></a></font><font face=\"Verdana\" style" 
   condition: 
      1 of them
}