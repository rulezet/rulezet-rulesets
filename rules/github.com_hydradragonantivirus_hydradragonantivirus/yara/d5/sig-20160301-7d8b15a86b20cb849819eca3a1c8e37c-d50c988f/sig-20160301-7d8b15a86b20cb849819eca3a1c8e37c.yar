rule sig_20160301_7d8b15a86b20cb849819eca3a1c8e37c {
  meta:
    description = "datamaliciousorder - file 20160301_7d8b15a86b20cb849819eca3a1c8e37c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "941ace7a11c74a4853ea80a2a8ae1eca115f1aa8ba8eceedff2e9c8e7442f28d"

  strings:
    $s1  = "return WScript.CreateObject(qdlLE);" fullword ascii
    $s2  = "var Aq = \"%TEMP%\\\\\";" fullword ascii
    $s3  = "function psSS(qdlLE) {" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + NAhgdno + \".F\" + XwQVnEqbrm + qGRej + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var OG = true  , ZZDj = wst[7] + \"\" + wst[9];" fullword ascii
    $s6  = "var wst = (uSk + \"TTP\" + \" ATFxzgY RFRUe XML ream St vAYGhZtq AD ROiUiru OD\").split(\" \");" fullword ascii
    $s7  = "psISB.open(mOIFb,kDMNq,false);" fullword ascii
    $s8  = "function Wibv(OyOXN,MARiY) {" fullword ascii
    $s9  = "function LlDP(kkDir,vxGig) {" fullword ascii
    $s10 = "function ROaFwZSf() {" fullword ascii
    $s11 = "function UvLO(kROrm) {" fullword ascii
    $s12 = "if (((new Date())>0,7616029888)) {" fullword ascii
    $s13 = "if (dnOcV == 948-748){return true;} else {return false;}" fullword ascii
    $s14 = "function XLKq(kyZJC) {" fullword ascii
    $s15 = "function JckPd(OoGwVX) {" fullword ascii
    $s16 = "return kyZJC.status;" fullword ascii
    $s17 = "function MbJS(psISB,kDMNq,mOIFb) {" fullword ascii
    $s18 = "function lzTA(DNOrj) {" fullword ascii
    $s19 = "function OftXueKUF(RUosghHpZdF) {" fullword ascii
    $s20 = "function MvDa(acmiS) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}