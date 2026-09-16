rule Webshell_HYTop_AppPack_2005_RID309F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2005.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:47:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb" 
   condition: 
      all of them
}