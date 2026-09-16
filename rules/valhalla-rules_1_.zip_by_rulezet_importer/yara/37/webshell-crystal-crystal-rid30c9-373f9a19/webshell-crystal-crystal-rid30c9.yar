rule Webshell_Crystal_Crystal_RID30C9 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Crystal.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:54:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value" 
      $s6 = "\" href=\"?act=tools\"><font color=#CC0000 size=\"3\">Tools</font></a></span></f" 
   condition: 
      all of them
}