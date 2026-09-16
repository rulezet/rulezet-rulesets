rule Webshell_Ani_Shell_RID2E15 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Ani-Shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:59:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$Python_CODE = \"I" 
      $s6 = "$passwordPrompt = \"\\n=================================================" 
      $s7 = "fputs ($sockfd ,\"\\n===============================================" 
   condition: 
      1 of them
}