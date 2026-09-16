rule sig_20160310_127f74ace1e890fefa48a2cc7f5d6697 {
  meta:
    description = "datamaliciousorder - file 20160310_127f74ace1e890fefa48a2cc7f5d6697.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32e95adbd03b6e1156fe43429ac53e6ef296de73dcffe7a3111f9ad6e5b751c3"

  strings:
    $s1  = "return ioutIgn[0] + ioutIgn[2] + ioutIgn[4] + \".F\" + ioutIgn[7] + ioutIgn[9] + ioutIgn[12] + ioutIgn[14];" fullword ascii
    $s2  = "var TX = true  , FHRb = Ycx[7] + Ycx[9] + Ycx[11];" fullword ascii
    $s3  = "gkqpJ.open(BvdAM,HzeHx,false);" fullword ascii
    $s4  = "var ioutIgn = \"Sc CTcIuom r rpKbQtyDE ipting XgKwdDV Riu ile aRXwoYpfSeyTfu System ys SNNnl Obj KeTMMZ ect mINgyom\".split(\" " ascii
    $s5  = "var Ycx = (\"2.XMLHTTP XumFSsS vQhKA XML ream St UakAZwUq AD CdslTXU O oIhJ D\").split(\" \");" fullword ascii
    $s6  = "function eLhWRuddk(elRYjSmvFgS) {" fullword ascii
    $s7  = "if (vWyGG == 1006-806){return true;} else {return false;}" fullword ascii
    $s8  = "function mfut(XQgfl) {" fullword ascii
    $s9  = "return EBPr.ExpandEnvironmentStrings(uKqZx);" fullword ascii
    $s10 = "function UkJHgrh(EBPr,uKqZx) {" fullword ascii
    $s11 = "function wplu(UpaOe) {" fullword ascii
    $s12 = "function hmYRj(AxdJEH) {" fullword ascii
    $s13 = "SJA = u; break; " fullword ascii
    $s14 = "function PJKD(YhOTQ,axANn) {" fullword ascii
    $s15 = "function eoCsWoC(fQrX) {" fullword ascii
    $s16 = "function RqzX(lacQK,AvcxK) {" fullword ascii
    $s17 = "function OqxgtBYM() {" fullword ascii
    $s18 = "return UkJHgrh(oP,kqdhD[328-322]+kqdhD[501-494]+kqdhD[709-701]);" fullword ascii
    $s19 = "function Rnoc(THRDw) {" fullword ascii
    $s20 = "function lDAA(ZFRSc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}