rule aspbackdoor_entice {
   meta:
      description = "Disclosed hacktool set (old stuff) - file entice.asp"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "e273a1b9ef4a00ae4a5d435c3c9c99ee887cb183"
      id = "68c61920-9c3c-5bfe-976c-346b258bb406"
   strings:
      $s0 = "<Form Name=\"FormPst\" Method=\"Post\" Action=\"entice.asp\">" fullword ascii
      $s2 = "if left(trim(request(\"sqllanguage\")),6)=\"select\" then" fullword ascii
      $s4 = "conndb.Execute(sqllanguage)" fullword ascii
      $s5 = "<!--#include file=sqlconn.asp-->" fullword ascii
      $s6 = "rstsql=\"select * from \"&rstable(\"table_name\")" fullword ascii
   condition:
      all of them
}