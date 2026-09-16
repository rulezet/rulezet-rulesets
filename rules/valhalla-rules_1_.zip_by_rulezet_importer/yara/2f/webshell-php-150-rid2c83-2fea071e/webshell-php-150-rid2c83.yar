rule Webshell_PHP_150_RID2C83 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 150.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:52:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "HJ3HjqxclkZfp" 
      $s1 = "<? eval(gzinflate(base64_decode('" fullword
   condition: 
      all of them
}