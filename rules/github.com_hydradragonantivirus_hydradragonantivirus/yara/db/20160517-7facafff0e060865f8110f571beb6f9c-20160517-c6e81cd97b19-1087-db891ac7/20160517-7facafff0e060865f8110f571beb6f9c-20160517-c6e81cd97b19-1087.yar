rule _20160517_7facafff0e060865f8110f571beb6f9c_20160517_c6e81cd97b19_1087 {
  meta:
    description = "datamaliciousorder - from files 20160517_7facafff0e060865f8110f571beb6f9c.js, 20160517_c6e81cd97b1961e438b5aa956f031620.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84a881cedf88a66609948a6849cd2aca8ee82e594f3bbd09602dc3716cb3632e"
    hash2       = "c3ddbbd491cad92ee4bd0753bd7571eb9d08bf0315a8ba2b49b79a3cce2b1636"

  strings:
    $s1 = "var nConverts1 /* m  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* m  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* m  */;};" fullword ascii
    $s4 = "batch =/* m  */ \"R\" + \"esponseB\"/* m  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s5 = "var enjoy1 /* m  */ = false;" fullword ascii
    $s6 = "could = /* m  */(/* m  */\"noitisop\").split(''/* m  */).reverse(/* m  */).join('');" fullword ascii
    $s7 = "enjoy1 /* m  */ /* m  */= true;/* m  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}