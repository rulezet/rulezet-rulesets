rule Webshell_aZRaiLPhp_v1_0_php_RID312D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file aZRaiLPhp v1.0.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:11:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "azrailphp" 
      $s1 = "<br><center><INPUT TYPE='SUBMIT' NAME='dy' VALUE='Dosya Yolla!'></center>" 
      $s3 = "<center><INPUT TYPE='submit' name='okmf' value='TAMAM'></center>" 
   condition: 
      2 of them
}