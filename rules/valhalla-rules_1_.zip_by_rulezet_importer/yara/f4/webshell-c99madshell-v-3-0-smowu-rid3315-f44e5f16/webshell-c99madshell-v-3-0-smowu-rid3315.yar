rule Webshell_C99madShell_v_3_0_smowu_RID3315 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file smowu.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:32:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "<tr><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>:: Enter ::</b><for" 
      $s8 = "<p><font color=red>Wordpress Not Found! <input type=text id=\"wp_pat\"><input ty" 
   condition: 
      1 of them
}