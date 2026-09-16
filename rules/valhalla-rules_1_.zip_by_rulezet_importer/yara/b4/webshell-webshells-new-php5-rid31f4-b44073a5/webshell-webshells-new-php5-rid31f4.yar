rule Webshell_webshells_new_php5_RID31F4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file php5.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:44:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?$_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_u" 
   condition: 
      all of them
}