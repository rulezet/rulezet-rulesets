rule sig_20160514_269253d8b514ecf350571b25fce089cc {
  meta:
    description = "datamaliciousorder - file 20160514_269253d8b514ecf350571b25fce089cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a922f1c348c44d1468317fe78108576766465ad73049e144f5dab7f5959cf8d"

  strings:
    $s1  = "while (PdjPX < OlNu - (4522 + 2001 - 6521)) {" fullword ascii
    $s2  = "function Eldyn(dfegg) {" fullword ascii
    $s3  = "function tEt() {" fullword ascii
    $s4  = "return IvnQ;" fullword ascii
    $s5  = "function MPz() {" fullword ascii
    $s6  = "function ORZ() {" fullword ascii
    $s7  = "return uYAND;" fullword ascii
    $s8  = "return KNjnA;" fullword ascii
    $s9  = "return qNRuRyJ;" fullword ascii
    $s10 = "return VrJysY;" fullword ascii
    $s11 = "function qhhU() {" fullword ascii
    $s12 = "function rclsbV(cSx) {" fullword ascii
    $s13 = "function pHT() {" fullword ascii
    $s14 = "return Kysuz;" fullword ascii
    $s15 = "if (Jzj == false) {" fullword ascii
    $s16 = "function ppgHVhR() {" fullword ascii
    $s17 = "function aYbAa() {" fullword ascii
    $s18 = "return agKqEFJ;" fullword ascii
    $s19 = "function KvtAIYK(nVwp) {" fullword ascii
    $s20 = "return JbgA;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}