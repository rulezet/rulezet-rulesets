rule DKShell_f0772be3c95802a2d1e7a4a3f5a45dcdef6997f3_RID3552 : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:08:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7ea49d5c29f1242f81f2393b514798ff7caccb50d46c60bdfcf61db00043473b"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<?php Error_Reporting(0); $s_pass = \"" ascii
      $s2 = "$s_func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on" ascii
   condition: 
      ( uint16 ( 0 ) == 0x3c0a and filesize < 300KB and all of them )
}