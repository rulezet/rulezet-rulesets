rule Webshell_Ayyildiz_Tim___AYT__Shell_v_2_1_Biz_html_RID39CD : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.html.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:19:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Ayyildiz" 
      $s1 = "TouCh By iJOo" 
      $s2 = "First we check if there has been asked for a working directory" 
      $s3 = "http://ayyildiz.org/images/whosonline2.gif" 
   condition: 
      2 of them
}