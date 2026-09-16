rule Webshell_mumaasp_com_RID2F38 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file mumaasp.com.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:47:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "&9K_)P82ai,A}I92]R\"q!C:RZ}S6]=PaTTR" 
   condition: 
      all of them
}