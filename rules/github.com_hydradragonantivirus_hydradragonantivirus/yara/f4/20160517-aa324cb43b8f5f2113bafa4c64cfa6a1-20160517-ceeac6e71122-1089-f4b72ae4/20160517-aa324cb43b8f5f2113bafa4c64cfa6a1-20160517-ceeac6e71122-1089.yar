rule _20160517_aa324cb43b8f5f2113bafa4c64cfa6a1_20160517_ceeac6e71122_1089 {
  meta:
    description = "datamaliciousorder - from files 20160517_aa324cb43b8f5f2113bafa4c64cfa6a1.js, 20160517_ceeac6e7112289144792365803951854.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8ba58943b83a1da85dac126e00994f5a95c4dcd342d96da742c596de262bc33"
    hash2       = "39893b180827a55b9a6c5f3e5d6b46fbd809b594b9baba2f3eb6029f02edbd03"

  strings:
    $s1 = "var nConverts1 /* X  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* X  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* X  */;};" fullword ascii
    $s4 = "var enjoy1 /* X  */ = false;" fullword ascii
    $s5 = "batch =/* X  */ \"R\" + \"esponseB\"/* X  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s6 = "enjoy1 /* X  */ /* X  */= true;/* X  */" fullword ascii
    $s7 = "could = /* X  */(/* X  */\"noitisop\").split(''/* X  */).reverse(/* X  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}