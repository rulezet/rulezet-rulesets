rule sig_20160209_8c15dd2bac472b37f8fc1fd909ee8367 {
  meta:
    description = "datamaliciousorder - file 20160209_8c15dd2bac472b37f8fc1fd909ee8367.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f82ca27c702c4683e0be231acd6e0704fb189bd78f006607c07723fad2930fdd"

  strings:
    $s1 = "var a7='555C535E0D0A020B24011C1405101001070C4A070B095E3C5E170114050C050A0A0D09160B0B1E0F05164A070B095E17565E55505151545653505352" ascii
    $s2 = "88+x81+g14+c76+'= i;'+' bre'+'ak'+'; }'+c96+p61+n67+' (e'+'r)'+' { '+'};'+l17+i53;this[v30](s87);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}