rule Webshell_FSO_s_ajan_RID2E59 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file ajan.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:10:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "entrika.write \"BinaryStream.SaveToFile" 
   condition: 
      all of them
}