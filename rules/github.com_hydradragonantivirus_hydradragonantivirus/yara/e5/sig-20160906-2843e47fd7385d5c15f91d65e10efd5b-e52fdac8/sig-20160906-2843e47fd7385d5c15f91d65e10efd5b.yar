rule sig_20160906_2843e47fd7385d5c15f91d65e10efd5b {
  meta:
    description = "datamaliciousorder - file 20160906_2843e47fd7385d5c15f91d65e10efd5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8258c74751e9a95726f289757dab64e256b54a6c8e89a89c48538a55360cec55"

  strings:
    $s1  = "return jgeto5;" fullword ascii
    $s2  = "function xyfnekfy3() {" fullword ascii
    $s3  = "function ozpibba5() {" fullword ascii
    $s4  = "function ebure3() {" fullword ascii
    $s5  = "function uzsykfannyv7() {" fullword ascii
    $s6  = "function ozulivhi4() {" fullword ascii
    $s7  = "function hatbedzoqxu4() {" fullword ascii
    $s8  = "return lpulxyluj0;" fullword ascii
    $s9  = "function hwomdi5() {" fullword ascii
    $s10 = "function afbalxyt5() {" fullword ascii
    $s11 = "return rivagyxy9;" fullword ascii
    $s12 = "function warrobuj6() {" fullword ascii
    $s13 = "return ihmilzuhulb3;" fullword ascii
    $s14 = "return izbugyti0;" fullword ascii
    $s15 = "function ehsyxs3() {" fullword ascii
    $s16 = "function fofi5() {" fullword ascii
    $s17 = "function rnivxonhowip9() {" fullword ascii
    $s18 = "function irkofukim6() {" fullword ascii
    $s19 = "function izimhoxzi4() {" fullword ascii
    $s20 = "return rxymo2;" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    8 of them
}