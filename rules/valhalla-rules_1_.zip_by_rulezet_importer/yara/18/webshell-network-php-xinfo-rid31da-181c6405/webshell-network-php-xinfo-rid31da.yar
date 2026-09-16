rule Webshell_network_php_xinfo_RID31DA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files network.php.php.txt, xinfo.php.php.txt, nfm.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:40:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2601b6fc1579f263d2f3960ce775df70"
      hash2 = "401fbae5f10283051c39e640b77e4c26"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = ".textbox { background: White; border: 1px #000000 solid; color: #000099; font-fa" 
      $s2 = "<input class='inputbox' type='text' name='pass_de' size=50 onclick=this.value=''" 
   condition: 
      all of them
}