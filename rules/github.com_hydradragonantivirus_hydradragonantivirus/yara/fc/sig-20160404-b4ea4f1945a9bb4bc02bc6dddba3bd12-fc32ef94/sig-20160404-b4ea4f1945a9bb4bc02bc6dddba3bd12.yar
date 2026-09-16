rule sig_20160404_b4ea4f1945a9bb4bc02bc6dddba3bd12 {
  meta:
    description = "datamaliciousorder - file 20160404_b4ea4f1945a9bb4bc02bc6dddba3bd12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb644f9ba1bf2e7c6f7ff107be2651eb3306037780aa19660d1980344dd1adec"

  strings:
    $s1  = "var ws = true  , lZiI = IGc[7] + IGc[9] + IGc[11];" fullword ascii
    $s2  = "return KCrNAIg[0] + KCrNAIg[2] + KCrNAIg[4] + \".F\" + KCrNAIg[7] + KCrNAIg[9] + KCrNAIg[12] + KCrNAIg[14];" fullword ascii
    $s3  = "wZcL.open(FMhci,ACNTM,false);" fullword ascii
    $s4  = "var KCrNAIg = gXnVW(UHClKlWCpD+\" \"+\"System VT uZroS Obj yiivpX ect xWeSrPG gCpTI\", \" \");" fullword ascii
    $s5  = "var IGc = (\"2.XMLHTTP wXuVAvJ AZxHT XML ream St MjmRFBKV AD RdWsqvE O Trij D\").split(\" \");" fullword ascii
    $s6  = "function mRqTd(GodBKc) {" fullword ascii
    $s7  = "function WomHeK(vRXaBGl) {" fullword ascii
    $s8  = "return uMPLgCw;" fullword ascii
    $s9  = "function WOXq(ZjbBk) {" fullword ascii
    $s10 = "if(S>=A.length) {break;}" fullword ascii
    $s11 = "function mRUkV(oksJitxw,cmQn) {" fullword ascii
    $s12 = "function ZiPFPy(UhaG,xKdgHV) {" fullword ascii
    $s13 = "function gXnVW(ZTz,eMFri) {" fullword ascii
    $s14 = "function QnCS(EuOqc) {" fullword ascii
    $s15 = "return ZTz.split(eMFri);" fullword ascii
    $s16 = "function IggLv(JVkUqu) {" fullword ascii
    $s17 = "return EyRHT.status;" fullword ascii
    $s18 = "function ppLNBHfB(Tuv) {" fullword ascii
    $s19 = "clPMH[SOmE[298-298]](bFYVrQ);" fullword ascii
    $s20 = "function fkiX(TLBXj) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}