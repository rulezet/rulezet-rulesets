rule Webshell_multiple_php_webshells_2_RID3472 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated "
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:30:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "elseif (!empty($ft)) {echo \"<center><b>Manually selected type is incorrect. I" 
      $s1 = "else {echo \"<center><b>Unknown extension (\".$ext.\"), please, select type ma" 
      $s3 = "$s = \"!^(\".implode(\"|\",$tmp).\")$!i\";" fullword
   condition: 
      all of them
}