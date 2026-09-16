rule _20160517_23635ce17ff4f6139e54b3a4db85046b_20160517_8bf2af99a796_1070 {
  meta:
    description = "datamaliciousorder - from files 20160517_23635ce17ff4f6139e54b3a4db85046b.js, 20160517_8bf2af99a7962fb2bf729cdd35070789.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81dfa7cd4588b2cef8960ca3bcd8be26b9a3478cef1db30ec1967b633df771d7"
    hash2       = "1d8bc937a31b1e312bda0fe55c785f8284d7a97eb84198e8901e25ef0a12ba49"

  strings:
    $s1 = "var nConverts1 /* R  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* R  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* R  */;};" fullword ascii
    $s4 = "could = /* R  */(/* R  */\"noitisop\").split(''/* R  */).reverse(/* R  */).join('');" fullword ascii
    $s5 = "batch =/* R  */ \"R\" + \"esponseB\"/* R  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s6 = "enjoy1 /* R  */ /* R  */= true;/* R  */" fullword ascii
    $s7 = "var enjoy1 /* R  */ = false;" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}