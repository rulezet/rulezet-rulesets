rule Webshell_r57_1_4_0_RID2D36 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file r57.1.4.0.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:22:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "@ini_set('error_log',NULL);" fullword
      $s6 = "$pass='abcdef1234567890abcdef1234567890';" fullword
      $s7 = "@ini_restore(\"disable_functions\");" fullword
      $s9 = "@ini_restore(\"safe_mode_exec_dir\");" fullword
   condition: 
      all of them
}