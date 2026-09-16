rule Webshell_caidao_shell_hkmjj_RID31F1 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file hkmjj.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:44:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  " fullword
   condition: 
      all of them
}