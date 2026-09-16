rule aspbackdoor_entice_RID2E71 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file entice.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 11:14:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<Form Name=\"FormPst\" Method=\"Post\" Action=\"entice.asp\">" fullword ascii
      $s2 = "if left(trim(request(\"sqllanguage\")),6)=\"select\" then" fullword ascii
      $s4 = "conndb.Execute(sqllanguage)" fullword ascii
      $s5 = "<!--#include file=sqlconn.asp-->" fullword ascii
      $s6 = "rstsql=\"select * from \"&rstable(\"table_name\")" fullword ascii
   condition: 
      all of them
}