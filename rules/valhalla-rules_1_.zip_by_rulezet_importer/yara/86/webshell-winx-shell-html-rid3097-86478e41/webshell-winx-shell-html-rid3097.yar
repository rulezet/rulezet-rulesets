rule Webshell_WinX_Shell_html_RID3097 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file WinX Shell.html.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:46:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "WinX Shell" 
      $s1 = "Created by greenwood from n57" 
      $s2 = "<td><font color=\\\"#990000\\\">Win Dir:</font></td>" 
   condition: 
      2 of them
}