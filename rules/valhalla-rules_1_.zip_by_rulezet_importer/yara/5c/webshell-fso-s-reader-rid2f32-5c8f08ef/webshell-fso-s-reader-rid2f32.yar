rule Webshell_FSO_s_reader_RID2F32 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file reader.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:46:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "mailto:mailbomb@hotmail." 
   condition: 
      all of them
}