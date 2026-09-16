rule Webshell_webshell_cnseay02_1_RID31D0 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file webshell-cnseay02-1.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:38:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "(93).$_uU(41).$_uU(59);$_fF=$_uU(99).$_uU(114).$_uU(101).$_uU(97).$_uU(116).$_uU" 
   condition: 
      all of them
}