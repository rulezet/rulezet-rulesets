rule Webshell_caidao_shell_ice_RID310E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ice.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:06:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%eval request(\"ice\")%>" fullword
   condition: 
      all of them
}