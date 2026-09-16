rule sig_20160429_4d95f020401772a76cbb9e34b281a4ec {
  meta:
    description = "datamaliciousorder - file 20160429_4d95f020401772a76cbb9e34b281a4ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a79542fb7cc2d58c975f229cbd0ad3bfd905550ce0425d14c727ca7e5349890f"

  strings:
    $s1  = "while (AhfGCW < Wmt - (3900, 2302, 254, 1053, 6816, 3194, 3072, 7383, 6688, 5186, 2)) {" fullword ascii
    $s2  = "return KyL + qQABWQX + NcqPw + zXwYFe + Zxqq + sabdNs;" fullword ascii
    $s3  = "if (6 === true) {" fullword ascii
    $s4  = "if (4 === true) {" fullword ascii
    $s5  = "switch (470) {" fullword ascii
    $s6  = "return pvH;" fullword ascii
    $s7  = "function gEyztdh() {" fullword ascii
    $s8  = "if (sJTOb === false) {" fullword ascii
    $s9  = "return QZbtZ;" fullword ascii
    $s10 = "var LoRPuL = false;" fullword ascii
    $s11 = "var zjvUj = true;" fullword ascii
    $s12 = "switch (uTN) {" fullword ascii
    $s13 = "function bDTV(FAvMFa, tAUo) {" fullword ascii
    $s14 = "var dAri = false;" fullword ascii
    $s15 = "PPs[KAwKsZ(\"010032054038\")](itpO, sWvSwV, false);" fullword ascii
    $s16 = "var jNkG = true;" fullword ascii
    $s17 = "return wvEAGvot;" fullword ascii
    $s18 = "var VJdB = false;" fullword ascii
    $s19 = "return vHJr;" fullword ascii
    $s20 = "return RLKMXNZ;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}