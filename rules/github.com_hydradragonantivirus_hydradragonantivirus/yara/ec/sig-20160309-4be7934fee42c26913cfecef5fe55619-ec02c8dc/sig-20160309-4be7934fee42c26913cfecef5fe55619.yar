rule sig_20160309_4be7934fee42c26913cfecef5fe55619 {
  meta:
    description = "datamaliciousorder - file 20160309_4be7934fee42c26913cfecef5fe55619.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "defe8bc8d227a9b48a40fb24e4657f4821af6fdb88722fa56b4101ad5ca271c5"

  strings:
    $s1  = "var sd = true  , fBVC = HoM[7] + HoM[9] + HoM[11];" fullword ascii
    $s2  = "return WoMfvUW[0] + WoMfvUW[2] + WoMfvUW[4] + \".F\" + WoMfvUW[7] + WoMfvUW[9] + WoMfvUW[12] + WoMfvUW[14];" fullword ascii
    $s3  = "usQoi.open(kvuTL,XTdLd,false);" fullword ascii
    $s4  = "var HoM = (\"2.XMLHTTP xItBRTt vjYmm XML ream St fHctAIhC AD iyPrOWQ O ozZK D\").split(\" \");" fullword ascii
    $s5  = "return shpb.ExpandEnvironmentStrings(BGVEL);" fullword ascii
    $s6  = "function WqPqHmLlq(ssqYr,TljZV,qrXLd,VzKY) {" fullword ascii
    $s7  = "function XAcYCBS(AQlb) {" fullword ascii
    $s8  = "function iIZvJUQH(VOa) {" fullword ascii
    $s9  = "function YAQd(xueMB) {" fullword ascii
    $s10 = "return XUwBcMz(Bn,YFZAe[581-575]+YFZAe[425-418]+YFZAe[153-145]);" fullword ascii
    $s11 = "if (xueMB == 581-381){return true;} else {return false;}" fullword ascii
    $s12 = "function XUwBcMz(shpb,BGVEL) {" fullword ascii
    $s13 = "function hXjv(PCyax,DOFKX) {" fullword ascii
    $s14 = "return ExBNI.status;" fullword ascii
    $s15 = "return RYHEJ;" fullword ascii
    $s16 = "function rFWl(KZjll) {" fullword ascii
    $s17 = "function ICZCg(hSgscN) {" fullword ascii
    $s18 = "return new ActiveXObject(hSgscN);" fullword ascii
    $s19 = "function qZftultw() {" fullword ascii
    $s20 = "if (KZjll > 150344-293){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}