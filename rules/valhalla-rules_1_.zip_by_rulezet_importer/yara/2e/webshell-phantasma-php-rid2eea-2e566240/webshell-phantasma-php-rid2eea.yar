rule Webshell_PHANTASMA_php_RID2EEA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file PHANTASMA.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:34:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = ">[*] Safemode Mode Run</DIV>" 
      $s1 = "$file1 - $file2 - <a href=$SCRIPT_NAME?$QUERY_STRING&see=$file>$file</a><br>" 
      $s2 = "[*] Spawning Shell" 
      $s3 = "Cha0s" 
   condition: 
      2 of them
}