rule sig_20160404_44a82a7e8735d26ad09731578157abfe {
  meta:
    description = "datamaliciousorder - file 20160404_44a82a7e8735d26ad09731578157abfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462a9e906bd1f3b1aa0122ab911d8287f10579b8ff8c59defbcb6dfdaa0f841c"

  strings:
    $s1  = "var LT = true  , ZFCL = mIp[7] + mIp[9] + mIp[11];" fullword ascii
    $s2  = "return OlBgKSB[0] + OlBgKSB[2] + OlBgKSB[4] + \".F\" + OlBgKSB[7] + OlBgKSB[9] + OlBgKSB[12] + OlBgKSB[14];" fullword ascii
    $s3  = "HrNU.open(hpgjD,LyezA,false);" fullword ascii
    $s4  = "var mIp = (\"2.XMLHTTP WFRWhDO nsCEK XML ream St oJCEJYqG AD hcdsrGV O cOxO D\").split(\" \");" fullword ascii
    $s5  = "var OlBgKSB = ocLjp(RivpiqoScZ+\" \"+\"System ZR nUDzl Obj drYozS ect vywKXNV GTMQB\", \" \");" fullword ascii
    $s6  = "function ByduxrvWR(YRqIOSwmAiJ) {" fullword ascii
    $s7  = "function ocLjp(gIN,Nvvng) {" fullword ascii
    $s8  = "function fmrm(oABXQ,mgRDx) {" fullword ascii
    $s9  = "function BwRZ(IJMkP) {" fullword ascii
    $s10 = "function YKRLb(pbvOZm) {" fullword ascii
    $s11 = "if (UfUHC > 186722-948){return true;} else {return false;}" fullword ascii
    $s12 = "return gIN.split(Nvvng);" fullword ascii
    $s13 = "return new ActiveXObject(CoTY);" fullword ascii
    $s14 = "function rEDD(Dxeac) {" fullword ascii
    $s15 = "function nlDYR(tCNiHFuy,NLdA) {" fullword ascii
    $s16 = "if (ICfLY == 934-734){return true;} else {return false;}" fullword ascii
    $s17 = "function LAwykgSV(cdqy) {" fullword ascii
    $s18 = "function KHtDhqh(WIol,OcyKq) {" fullword ascii
    $s19 = "function JlIpDS(pLKf,egaikw) {" fullword ascii
    $s20 = "return KHtDhqh(yE,DGiCp[687-681]+DGiCp[128-121]+DGiCp[911-903]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}