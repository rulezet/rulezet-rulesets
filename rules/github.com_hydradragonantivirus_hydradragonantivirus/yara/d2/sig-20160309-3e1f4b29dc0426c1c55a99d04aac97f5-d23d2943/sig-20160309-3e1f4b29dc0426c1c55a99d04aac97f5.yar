rule sig_20160309_3e1f4b29dc0426c1c55a99d04aac97f5 {
  meta:
    description = "datamaliciousorder - file 20160309_3e1f4b29dc0426c1c55a99d04aac97f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0376aab8b71de272fda366661410f9f8352429fda86b44adc4ee3ab90409f439"

  strings:
    $s1  = "return ahBHmPT[0] + ahBHmPT[2] + ahBHmPT[4] + \".F\" + ahBHmPT[7] + ahBHmPT[9] + ahBHmPT[12] + ahBHmPT[14];" fullword ascii
    $s2  = "var qB = true  , yDXX = Nzo[7] + Nzo[9] + Nzo[11];" fullword ascii
    $s3  = "var Nzo = (\"2.XMLHTTP KHexjpV QAQuL XML ream St rUMfElpk AD eOJOpQh O JwIk D\").split(\" \");" fullword ascii
    $s4  = "var ahBHmPT = \"Sc xFwWnVz r iifiCKajD ipting PmWRLdY jhQ ile TMKKVrhlaFkanK System pr Azxlt Obj RieeVU ect hInVBCo\".split(\" " ascii
    $s5  = "xGRAL.open(LvKmw,vknZP,false);" fullword ascii
    $s6  = "function LDjPD(Nbjcfx) {" fullword ascii
    $s7  = "return XpOKCri" fullword ascii
    $s8  = "function gMsM(xGRAL,vknZP,LvKmw) {" fullword ascii
    $s9  = "function IcDe(UXJXX) {" fullword ascii
    $s10 = "function xNLIztXW(mNWNV,VZLAgh) {" fullword ascii
    $s11 = "function MBZF(YgXVo) {" fullword ascii
    $s12 = "function zauJ(RcQrR) {" fullword ascii
    $s13 = "return PEykaCS(tt,tlGax[548-542]+tlGax[1006-999]+tlGax[543-535]);" fullword ascii
    $s14 = "function fxLl(VzAtZ) {" fullword ascii
    $s15 = "function ieujxbaKM(TzJdt,GkCJY,SPigw,CUPv) {" fullword ascii
    $s16 = "function ysva(VISnG,EPzZz) {" fullword ascii
    $s17 = "return qdkoi;" fullword ascii
    $s18 = "return hiHk.ExpandEnvironmentStrings(ZPNgq);" fullword ascii
    $s19 = "if(S>=X.length) {break;}" fullword ascii
    $s20 = "function sEXIwgJ(Ctfs) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}