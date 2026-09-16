rule WebShell_hiddens_shell_v1_RID30E2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file hiddens shell v1.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:58:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U" 
   condition: 
      all of them
}