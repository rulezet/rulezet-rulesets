rule _20160517_4a8229a47e9cbc21fe6dcef6a00f09de_20160517_9acccacc5c73_1076 {
  meta:
    description = "datamaliciousorder - from files 20160517_4a8229a47e9cbc21fe6dcef6a00f09de.js, 20160517_9acccacc5c73b90f57a7a0cd78983633.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6059be19b79ac6f80c6bfd34d41ea4dc9e1f64a65fc74eb3c6c1c511cb1ab9c3"
    hash2       = "c08fec58535a2cf592d85a454c18bca731ea706388322e5bb2c22bc5d5754ecc"

  strings:
    $s1 = "var nConverts1 /* e  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* e  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* e  */;};" fullword ascii
    $s4 = "enjoy1 /* e  */ /* e  */= true;/* e  */" fullword ascii
    $s5 = "var enjoy1 /* e  */ = false;" fullword ascii
    $s6 = "could = /* e  */(/* e  */\"noitisop\").split(''/* e  */).reverse(/* e  */).join('');" fullword ascii
    $s7 = "batch =/* e  */ \"R\" + \"esponseB\"/* e  */ + \"ydo\".split('').reverse().join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}