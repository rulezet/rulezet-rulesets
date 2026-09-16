rule sig_20160303_1bb4c703f33bf7ce4ec80a55f9fc4607 {
  meta:
    description = "datamaliciousorder - file 20160303_1bb4c703f33bf7ce4ec80a55f9fc4607.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38ebcbaec7b60a7854820d0aa97cf8196e9f3455a27fd6700360b67bdb038244"

  strings:
    $s1  = "var GKBFm = \"wHSMcq xZA pt.Shell SdJFrFd Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var DW = true  , yMhe = dea[7] + \"\" + dea[9];" fullword ascii
    $s3  = "return qBDNyFQ[0] + qBDNyFQ[2] + qBDNyFQ[4] + \".F\" + qBDNyFQ[7] + qBDNyFQ[9] + qBDNyFQ[12] + qBDNyFQ[14];" fullword ascii
    $s4  = "var dea = (pqp + \"TTP\" + \" wWIagFa aXWRY XML ream St vZRgQtYu AD fXoGyZL OD\").split(\" \");" fullword ascii
    $s5  = "Depnw.open(YyTVC,MPaZA,false);" fullword ascii
    $s6  = "function aFrL(rFCqe) {" fullword ascii
    $s7  = "function nuqs(Depnw,MPaZA,YyTVC) {" fullword ascii
    $s8  = "function zIHq(PlZrr) {" fullword ascii
    $s9  = "if (((new Date())>0,7445832888)) {" fullword ascii
    $s10 = "return IGVxr;" fullword ascii
    $s11 = "function AifF(pVThL,PGrVs) {" fullword ascii
    $s12 = "if(s>=E.length) {break;}" fullword ascii
    $s13 = "function EOqz(mWHfq) {" fullword ascii
    $s14 = "function SHyWytA(PPms) {" fullword ascii
    $s15 = "function VNYU(NORDh) {" fullword ascii
    $s16 = "function SeTa(zLTYV) {" fullword ascii
    $s17 = "return tbKExYF" fullword ascii
    $s18 = "if (NORDh > 184223-564){return true;} else {return false;}" fullword ascii
    $s19 = "function lcIZ(yqHwf) {" fullword ascii
    $s20 = "return new ActiveXObject(PjiJCx);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}