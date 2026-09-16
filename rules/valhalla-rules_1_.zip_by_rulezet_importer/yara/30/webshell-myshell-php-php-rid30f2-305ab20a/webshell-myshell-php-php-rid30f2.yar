rule Webshell_myshell_php_php_RID30F2 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file myshell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:01:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "@chdir($work_dir) or ($shellOutput = \"MyShell: can't change directory." 
      $s1 = "echo \"<font color=$linkColor><b>MyShell file editor</font> File:<font color" 
      $s2 = " $fileEditInfo = \"&nbsp;&nbsp;:::::::&nbsp;&nbsp;Owner: <font color=$" 
   condition: 
      2 of them
}