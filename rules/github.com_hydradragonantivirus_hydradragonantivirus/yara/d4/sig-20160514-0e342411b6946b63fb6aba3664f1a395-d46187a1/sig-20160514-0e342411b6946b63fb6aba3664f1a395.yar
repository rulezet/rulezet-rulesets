rule sig_20160514_0e342411b6946b63fb6aba3664f1a395 {
  meta:
    description = "datamaliciousorder - file 20160514_0e342411b6946b63fb6aba3664f1a395.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81a1704488a47aa763f5340411d5c7feee75ec78626aef723d6c48e26d645c24"

  strings:
    $s1  = "while (cnXrQa < BuYMVq - (3817 + 2289 - 6104)) {" fullword ascii
    $s2  = "return SRun;" fullword ascii
    $s3  = "} catch (phostNl) {}" fullword ascii
    $s4  = "function pGBq() {" fullword ascii
    $s5  = "if (HHjrOf(38) != true) {" fullword ascii
    $s6  = "return dRuUFi;" fullword ascii
    $s7  = "return lVtLG;" fullword ascii
    $s8  = "function LVZGrM(epbIJx) {" fullword ascii
    $s9  = "function qJGLt(RBL, Rytw) {" fullword ascii
    $s10 = "function mXZ() {" fullword ascii
    $s11 = "return iwHl;" fullword ascii
    $s12 = "return TUSrUUUg;" fullword ascii
    $s13 = "function vbDttlD() {" fullword ascii
    $s14 = "return odAiWSd;" fullword ascii
    $s15 = "function sZr() {" fullword ascii
    $s16 = "return dPwDMs;" fullword ascii
    $s17 = "function JkHtgu(dfegg) {" fullword ascii
    $s18 = "var KzGRx = false;" fullword ascii
    $s19 = "function ipsLwr() {" fullword ascii
    $s20 = "function FSpkaoV() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}