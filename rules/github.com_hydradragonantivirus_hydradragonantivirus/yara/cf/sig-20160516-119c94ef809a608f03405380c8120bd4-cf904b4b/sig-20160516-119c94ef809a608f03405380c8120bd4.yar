rule sig_20160516_119c94ef809a608f03405380c8120bd4 {
  meta:
    description = "datamaliciousorder - file 20160516_119c94ef809a608f03405380c8120bd4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03cce8f9801286e82fec1012d25b72c759d215b943b20600a23fc08e7ebe175b"

  strings:
    $s1  = "while (sQhalA < swIY - (276 - 274)) {" fullword ascii
    $s2  = "function fbInIY(SuP) {" fullword ascii
    $s3  = "return dctmeR;" fullword ascii
    $s4  = "function vfhkyH() {" fullword ascii
    $s5  = "return wdkxT;" fullword ascii
    $s6  = "return OTRLJHu;" fullword ascii
    $s7  = "function JAOmBY() {" fullword ascii
    $s8  = "function pVbJdOE() {" fullword ascii
    $s9  = "function EJzpxS(iRAcNygQ) {" fullword ascii
    $s10 = "return zOIodvkj;" fullword ascii
    $s11 = "function yzaUac() {" fullword ascii
    $s12 = "if (GtRPnmM(\"erMqBeO\", 0) == true) {" fullword ascii
    $s13 = "function CqxciGp() {" fullword ascii
    $s14 = "return OpNWfvN;" fullword ascii
    $s15 = "return YWsfR;" fullword ascii
    $s16 = "function SGWY(yGVKM, zSvs) {" fullword ascii
    $s17 = "function SIHDy() {" fullword ascii
    $s18 = "function nmp() {" fullword ascii
    $s19 = "return VQPtKUH;" fullword ascii
    $s20 = "return npKot;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}