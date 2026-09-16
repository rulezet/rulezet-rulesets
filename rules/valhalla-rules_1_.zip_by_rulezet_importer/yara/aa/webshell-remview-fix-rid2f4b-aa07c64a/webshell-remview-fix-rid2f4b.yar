rule Webshell_remview_fix_RID2F4B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file remview_fix.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:51:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u" 
      $s5 = "echo \"<P><hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n" 
   condition: 
      1 of them
}