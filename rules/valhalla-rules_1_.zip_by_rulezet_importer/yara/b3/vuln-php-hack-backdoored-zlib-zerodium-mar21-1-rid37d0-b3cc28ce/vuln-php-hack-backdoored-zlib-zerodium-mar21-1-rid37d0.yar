rule VULN_PHP_Hack_Backdoored_Zlib_Zerodium_Mar21_1_RID37D0 : DEMO VULN {
   meta:
      description = "Detects backdoored PHP zlib version"
      author = "Florian Roth"
      reference = "https://www.bleepingcomputer.com/news/security/phps-git-server-hacked-to-add-backdoors-to-php-source-code/"
      date = "2021-03-29 17:54:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, VULN"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "REMOVETHIS: sold to zerodium, mid 2017" fullword ascii
      $x2 = "HTTP_USER_AGENTT" ascii fullword
   condition: 
      filesize < 3000KB and all of them
}