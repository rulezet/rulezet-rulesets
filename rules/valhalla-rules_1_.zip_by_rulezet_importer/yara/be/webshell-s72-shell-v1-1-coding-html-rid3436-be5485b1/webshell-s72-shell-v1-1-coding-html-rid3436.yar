rule Webshell_s72_Shell_v1_1_Coding_html_RID3436 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file s72 Shell v1.1 Coding.html.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:20:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Dizin</font></b></font><font face=\"Verdana\" style=\"font-size: 8pt\"><" 
      $s1 = "s72 Shell v1.0 Codinf by Cr@zy_King" 
      $s3 = "echo \"<p align=center>Dosya Zaten Bulunuyor</p>\"" 
   condition: 
      1 of them
}