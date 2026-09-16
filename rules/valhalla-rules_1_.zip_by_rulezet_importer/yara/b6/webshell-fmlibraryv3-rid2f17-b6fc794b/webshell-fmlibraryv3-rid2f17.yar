rule Webshell_fmlibraryv3_RID2F17 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file fmlibraryv3.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:42:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "ExeNewRs.CommandText = \"UPDATE \" & tablename & \" SET \" & ExeNewRsValues & \" WHER" 
   condition: 
      all of them
}