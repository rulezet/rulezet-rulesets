rule Webshell_c99_madnet_smowu_RID30ED : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file smowu.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:00:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "//Authentication" fullword
      $s1 = "$login = \"" fullword
      $s2 = "eval(gzinflate(base64_decode('" 
      $s4 = "//Pass" 
      $s5 = "$md5_pass = \"" 
      $s6 = "//If no pass then hash" 
   condition: 
      all of them
}