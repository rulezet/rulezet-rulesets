rule WebShell_Generic_1609_A_RID2F12 : DEMO FILE GEN T1505_003 WEBSHELL {
   meta:
      description = "Detects a PHP webshell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 11:41:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c817a490cfd4d6377c15c9ac9bcfa136f4a45ff5b40c74f15216c030f657d035"
      hash3 = "69b9d55ea2eb4a0d9cfe3b21b0c112c31ea197d1cb00493d1dddc78b90c5745e"
      tags = "DEMO, FILE, GEN, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "return $qwery45234dws($b);" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x3f3c and 1 of them )
}