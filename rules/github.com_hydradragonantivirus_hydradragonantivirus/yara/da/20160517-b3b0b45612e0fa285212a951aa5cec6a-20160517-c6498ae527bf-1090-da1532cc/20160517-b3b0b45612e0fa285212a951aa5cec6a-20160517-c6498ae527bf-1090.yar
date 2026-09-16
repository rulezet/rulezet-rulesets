rule _20160517_b3b0b45612e0fa285212a951aa5cec6a_20160517_c6498ae527bf_1090 {
  meta:
    description = "datamaliciousorder - from files 20160517_b3b0b45612e0fa285212a951aa5cec6a.js, 20160517_c6498ae527bf4662c781c194e6d47561.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fc32014cb5b87bd1e97ade28098e7e29e8762ced9fd454f471003544598906"
    hash2       = "31f3d7510b0617c9204e8280bb2cf5efb26cfcf352de5d5469e794e3bd1fde15"

  strings:
    $s1 = "var nConverts1 /* l  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* l  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* l  */;};" fullword ascii
    $s4 = "enjoy1 /* l  */ /* l  */= true;/* l  */" fullword ascii
    $s5 = "batch =/* l  */ \"R\" + \"esponseB\"/* l  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s6 = "could = /* l  */(/* l  */\"noitisop\").split(''/* l  */).reverse(/* l  */).join('');" fullword ascii
    $s7 = "var enjoy1 /* l  */ = false;" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}