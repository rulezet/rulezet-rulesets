rule sig_20160311_67279b8378a6d1b00c739b32a57c293e {
  meta:
    description = "datamaliciousorder - file 20160311_67279b8378a6d1b00c739b32a57c293e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "070e7854cb3f75608f5e00c136523cf12e251efbf3645654110e34a3a3bd7608"

  strings:
    $s1  = "return mTRQBZy[0] + mTRQBZy[2] + mTRQBZy[4] + \".F\" + mTRQBZy[7] + mTRQBZy[9] + mTRQBZy[12] + mTRQBZy[14];" fullword ascii
    $s2  = "var Yo = true  , cNYv = rXT[7] + rXT[9] + rXT[11];" fullword ascii
    $s3  = "ojVqa.open(uJoRO,GZmmd,false);" fullword ascii
    $s4  = "var rXT = (\"2.XMLHTTP tSEUilk JcjHm XML ream St kGhFSCsh AD ouHuAIg O zidz D\").split(\" \");" fullword ascii
    $s5  = "var mTRQBZy = \"Sc xcOUgJk r cManpHwEn ipting pgUgqcz fxw ile NpWxqcJaFQKylC System jN mJxhy Obj LKYZve ect ycJEtsj\".split(\" " ascii
    $s6  = "Fun = O; break; " fullword ascii
    $s7  = "if (PKTOn > 132971-522){return true;} else {return false;}" fullword ascii
    $s8  = "function kycD(FavoB) {" fullword ascii
    $s9  = "function SKiHuDZ(QQwl,mKdlh) {" fullword ascii
    $s10 = "function zSoV(srSFW) {" fullword ascii
    $s11 = "return QQwl.ExpandEnvironmentStrings(mKdlh);" fullword ascii
    $s12 = "return TEaZ.responseBody;" fullword ascii
    $s13 = "function fhbW(pbHbL) {" fullword ascii
    $s14 = "function UTCVwVuO(YxTub,tFxFWr) {" fullword ascii
    $s15 = "function kRAMa(fxKLTY) {" fullword ascii
    $s16 = "function lbTDt(bSrwaW) {" fullword ascii
    $s17 = "return pbHbL.status;" fullword ascii
    $s18 = "function lUzM(PKTOn) {" fullword ascii
    $s19 = "function rSri(rLTbt,nvmhY) {" fullword ascii
    $s20 = "function uQMK(ATbBI) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}