rule Webshell_caidao_shell_mdb_RID3110 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file mdb.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:06:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<% execute request(\"ice\")%>a " fullword
   condition: 
      all of them
}