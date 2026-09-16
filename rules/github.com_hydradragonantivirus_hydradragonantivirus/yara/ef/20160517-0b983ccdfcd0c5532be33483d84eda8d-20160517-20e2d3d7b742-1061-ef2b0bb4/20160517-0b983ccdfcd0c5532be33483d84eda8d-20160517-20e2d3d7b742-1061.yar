rule _20160517_0b983ccdfcd0c5532be33483d84eda8d_20160517_20e2d3d7b742_1061 {
  meta:
    description = "datamaliciousorder - from files 20160517_0b983ccdfcd0c5532be33483d84eda8d.js, 20160517_20e2d3d7b7428ec5c8880de409bbcd49.js, 20160517_76a6cfabfc8175be0fe8fc724b38045a.js, 20160517_dbca62935943c81962dc07e5818ec879.js, 20160517_ecbd3edb263dc92accc44bd1985e7ca3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5789092d3bcafdc51e1c51a047047e93e347117199941d648a6dc78ac9eac1bb"
    hash2       = "5a7ecde5496ab7cbf142d20046c27f7788e2d0d685bbefc2cd6817a1e293bf97"
    hash3       = "5bdb07f58353352e336664b2e5259caf437997a1f1ea9e3647b390191a299cba"
    hash4       = "991b839c6c1369c5c2dae50b5d635bc0412d5736f0f8054840d63c066a1c4753"
    hash5       = "979270d9a4a66d6a1c32c9c4dc5dfe0ce4d1aac7a3dde145c6c0e76e581a6b10"

  strings:
    $s1 = "var nConverts1 /* O  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* O  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* O  */;};" fullword ascii
    $s4 = "batch =/* O  */ \"R\" + \"esponseB\"/* O  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s5 = "enjoy1 /* O  */ /* O  */= true;/* O  */" fullword ascii
    $s6 = "var enjoy1 /* O  */ = false;" fullword ascii
    $s7 = "could = /* O  */(/* O  */\"noitisop\").split(''/* O  */).reverse(/* O  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}