rule sig_20160315_6370ba8ac34464c34f96794f5a03c2c4 {
  meta:
    description = "datamaliciousorder - file 20160315_6370ba8ac34464c34f96794f5a03c2c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2e57e34a42bf2f2d852284357500d81cb1ad2a9b07ea8dbaf51d7a879c47771"

  strings:
    $s1  = "var Ii = true  , oIpQ = JXs[7] + JXs[9] + JXs[11];" fullword ascii
    $s2  = "return CzYyjey[0] + CzYyjey[2] + CzYyjey[4] + \".F\" + CzYyjey[7] + CzYyjey[9] + CzYyjey[12] + CzYyjey[14];" fullword ascii
    $s3  = "var CzYyjey = UQwLW(\"Sc MmFEXKm r MMbwImvse ipting RwPHrXH TfD ile xdxWdtQZvIXQMH System OU xbewx Obj UHVHcb ect bjQCDcP UfVlF" ascii
    $s4  = "zYHIQ.open(hObCp,CRNkW,false);" fullword ascii
    $s5  = "var CzYyjey = UQwLW(\"Sc MmFEXKm r MMbwImvse ipting RwPHrXH TfD ile xdxWdtQZvIXQMH System OU xbewx Obj UHVHcb ect bjQCDcP UfVlF" ascii
    $s6  = "var JXs = (\"2.XMLHTTP NsWEEbc hhyvN XML ream St azIMVcUs AD fQiMzFo O uvnf D\").split(\" \");" fullword ascii
    $s7  = "function hsnHAeM(Gbqv) {" fullword ascii
    $s8  = "function WfwZbuNm() {" fullword ascii
    $s9  = "if(C>=E.length) {break;}" fullword ascii
    $s10 = "function pUkr(eNuTN,guNer) {" fullword ascii
    $s11 = "return WExDeB.position=808-808;" fullword ascii
    $s12 = "return scMJjVk(pP,gAbLL[255-249]+gAbLL[785-778]+gAbLL[797-789]);" fullword ascii
    $s13 = "if (aVpkI > 184771-889){return true;} else {return false;}" fullword ascii
    $s14 = "function eaFo(BwVYP) {" fullword ascii
    $s15 = "return new ActiveXObject(KYoPSp);" fullword ascii
    $s16 = "return VnSs.ExpandEnvironmentStrings(OXXiq);" fullword ascii
    $s17 = "function UQwLW(sCi,FlnGs) {" fullword ascii
    $s18 = "function ldTDASRKK(pywirXGAcZT) {" fullword ascii
    $s19 = "function xOkd(MwmQq) {" fullword ascii
    $s20 = "return sCi.split(FlnGs);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}