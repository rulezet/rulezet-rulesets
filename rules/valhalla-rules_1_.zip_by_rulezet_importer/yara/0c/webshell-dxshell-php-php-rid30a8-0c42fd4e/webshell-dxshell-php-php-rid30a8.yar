rule Webshell_DxShell_php_php_RID30A8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file DxShell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:49:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx" 
      $s2 = "print \"\\n\".'<tr><td width=100pt class=linelisting><nobr>POST (php eval)</td><" 
   condition: 
      1 of them
}