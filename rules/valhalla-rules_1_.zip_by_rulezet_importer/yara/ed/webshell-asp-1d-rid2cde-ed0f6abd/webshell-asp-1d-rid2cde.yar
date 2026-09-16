rule Webshell_asp_1d_RID2CDE : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 1d.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:07:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO" 
   condition: 
      all of them
}