rule sig_20160323_34ab38f5397d8c7ae7e80255cda8907a {
  meta:
    description = "datamaliciousorder - file 20160323_34ab38f5397d8c7ae7e80255cda8907a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcde5731b32e64188170dc3b0142e52cae78e25d8061e2dc162565c07f267451"

  strings:
    $s1  = "return WScript.CreateObject(rfEPw);" fullword ascii
    $s2  = "var ke = true  , BbCk = ThY[7] + ThY[9] + ThY[11];" fullword ascii
    $s3  = "return uDFobNn[0] + uDFobNn[2] + uDFobNn[4] + \".F\" + uDFobNn[7] + uDFobNn[9] + uDFobNn[12] + uDFobNn[14];" fullword ascii
    $s4  = "var uDFobNn = acfau(fTozkvgrgR+\" \"+\"System Oh QTzyd Obj fMIAYL ect yBWSGZE mejhD\", \" \");" fullword ascii
    $s5  = "ZoLE.open(hswYf,NPRbw,false);" fullword ascii
    $s6  = "var ThY = (\"2.XMLHTTP Kdpxsmq XMhBn XML ream St JZGPxtwP AD vfUMGYA O gmtV D\").split(\" \");" fullword ascii
    $s7  = "function TTwXWzu(hBim) {" fullword ascii
    $s8  = "return aXYb.ExpandEnvironmentStrings(kmdum);" fullword ascii
    $s9  = "OMd = h; break; " fullword ascii
    $s10 = "return TMt.size;" fullword ascii
    $s11 = "function APDA(aWnDA) {" fullword ascii
    $s12 = "function Rvny(LEUuU) {" fullword ascii
    $s13 = "return LJLUhFx(Gt,hXYKu[415-409]+hXYKu[786-779]+hXYKu[294-286]);" fullword ascii
    $s14 = "function acfau(rRi,zRJwN) {" fullword ascii
    $s15 = "return PXYKc;" fullword ascii
    $s16 = "function kIKRD(RIcrnB) {" fullword ascii
    $s17 = "return mFthq.status;" fullword ascii
    $s18 = "function JdnH(mFthq) {" fullword ascii
    $s19 = "return hBim[uWEMCb[0]];" fullword ascii
    $s20 = "function LJLUhFx(aXYb,kmdum) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}