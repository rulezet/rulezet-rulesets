rule Webshell_xssshell_RID2E1C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file xssshell.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:00:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma" 
   condition: 
      all of them
}