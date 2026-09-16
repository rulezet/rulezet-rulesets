rule sig_20160324_ce1311fdcbff3b88afac8dcbe55ba5c4 {
  meta:
    description = "datamaliciousorder - file 20160324_ce1311fdcbff3b88afac8dcbe55ba5c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c869aaf674836102b9b7522defe1bb717944df56b6ff8e4281a6cd8a524a0968"

  strings:
    $s1  = "return WScript.CreateObject(teMSu);" fullword ascii
    $s2  = "var Rn = true  , mwau = OOz[7] + OOz[9] + OOz[11];" fullword ascii
    $s3  = "return FfBQKmd[0] + FfBQKmd[2] + FfBQKmd[4] + \".F\" + FfBQKmd[7] + FfBQKmd[9] + FfBQKmd[12] + FfBQKmd[14];" fullword ascii
    $s4  = "UybA.open(rHpeq,LHgSb,false);" fullword ascii
    $s5  = "var OOz = (\"2.XMLHTTP KijIYgX MSItJ XML ream St wuvGUIaB AD CCzbSML O szRO D\").split(\" \");" fullword ascii
    $s6  = "var FfBQKmd = gkVBl(LCHgqKEOoZ+\" \"+\"System YW hPPbR Obj FjUFkg ect NztTnVT QfLol\", \" \");" fullword ascii
    $s7  = "if (FIAHp > 183914-956){return true;} else {return false;}" fullword ascii
    $s8  = "return eWA.size;" fullword ascii
    $s9  = "function AOVe(ozmzd) {" fullword ascii
    $s10 = "function WXEuiIP(IieP,JTvYC) {" fullword ascii
    $s11 = "if (ybSKZ == 882-682){return true;} else {return false;}" fullword ascii
    $s12 = "if(o>=B.length) {break;}" fullword ascii
    $s13 = "return jNNaT;" fullword ascii
    $s14 = "bNU = o; break; " fullword ascii
    $s15 = "return Fik.split(ZwEHA);" fullword ascii
    $s16 = "function zeSMJsr(kpXN) {" fullword ascii
    $s17 = "function KYCwkotsy(ZUVYw) {" fullword ascii
    $s18 = "return kpXN[ILHEWX[0]];" fullword ascii
    $s19 = "function sejb(VmfbG) {" fullword ascii
    $s20 = "function hyyjA(IuudLj) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}