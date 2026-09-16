rule sig_20160404_562bc439ebac66eecc8eae2e8c60d932 {
  meta:
    description = "datamaliciousorder - file 20160404_562bc439ebac66eecc8eae2e8c60d932.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef51ab74c8d016c44bc31a3b368fb5cff5176f1dabc657eb5652f1a4cc459292"

  strings:
    $s1  = "return YKGUgqR[0] + YKGUgqR[2] + YKGUgqR[4] + \".F\" + YKGUgqR[7] + YKGUgqR[9] + YKGUgqR[12] + YKGUgqR[14];" fullword ascii
    $s2  = "var HH = true  , DqsB = kIm[7] + kIm[9] + kIm[11];" fullword ascii
    $s3  = "var YKGUgqR = jehsS(XQwnoAuizf+\" \"+\"System xW QgmDA Obj KbYxMf ect pjAcqXK htsPH\", \" \");" fullword ascii
    $s4  = "ckmV.open(cKNru,MbAEF,false);" fullword ascii
    $s5  = "if(c>=a.length) {break;}" fullword ascii
    $s6  = "function lzDGdJtn(texw) {" fullword ascii
    $s7  = "function SYypTcSQ(pax) {" fullword ascii
    $s8  = "return new ActiveXObject(WASU);" fullword ascii
    $s9  = "function tjuDOgjlx(qRbuteAzQEW) {" fullword ascii
    $s10 = "function QNtJ(Iztdm) {" fullword ascii
    $s11 = "function cHhe(MFYkE) {" fullword ascii
    $s12 = "if (e >= DxwFk.length) {break;}" fullword ascii
    $s13 = "return \"BTKqtrWJoOGlml\";" fullword ascii
    $s14 = "return WnFN[dqUOIO[0]];" fullword ascii
    $s15 = "function IQmMC(FeWmho) {" fullword ascii
    $s16 = "return ANxZoas;" fullword ascii
    $s17 = "function VtOD(sMjLm,MbAEF,cKNru) {" fullword ascii
    $s18 = "function iEgyI(spHOecWk,xDIL) {" fullword ascii
    $s19 = "if (Iztdm == 707-507){return true;} else {return false;}" fullword ascii
    $s20 = "function aKkpIGN(WnFN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}