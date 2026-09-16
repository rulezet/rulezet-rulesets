rule Webshell_xssshell_save_RID302A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file save.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:28:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "RawCommand = Command & COMMAND_SEPERATOR & Param & COMMAND_SEPERATOR & AttackID" 
      $s5 = "VictimID = fm_NStr(Victims(i))" 
   condition: 
      all of them
}