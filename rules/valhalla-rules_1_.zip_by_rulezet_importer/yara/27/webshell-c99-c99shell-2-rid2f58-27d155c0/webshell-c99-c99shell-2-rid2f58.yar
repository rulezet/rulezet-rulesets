rule Webshell_c99_c99shell_2_RID2F58 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files c99.php, c99shell.php, c99.php, c99shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:53:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d3f38a6dc54a73d304932d9227a739ec"
      hash2 = "157b4ac3c7ba3a36e546e81e9279eab5"
      hash3 = "048ccc01b873b40d57ce25a4c56ea717"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "$bindport_pass = \"c99\";" fullword
      $s5 = " else {echo \"<b>Execution PHP-code</b>\"; if (empty($eval_txt)) {$eval_txt = tr" 
   condition: 
      1 of them
}