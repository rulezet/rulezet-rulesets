rule sig_20160428_3fe6fc9ce6e7d0052b8e6e2267860b05 {
  meta:
    description = "datamaliciousorder - file 20160428_3fe6fc9ce6e7d0052b8e6e2267860b05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6932987823aeef79f43e4be247127cac87529f5bf79a5606da09ba91efdbe84"

  strings:
    $s1  = "BneOaaMwdYozGkcFbpYbv[BqkWwbKcqUmuXxaOjvAyd](\"G\" + \"ET\", \"http://rabitaforex.com/pw3ksl\", false);" fullword ascii
    $s2  = "function VhpSufWorGgmZtvSzoWre(QnkMirRutQprBeuFybSsl){HdnJvzJgdUtvQtiEceQzk[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function JjxOnkDkfIreUqkMefNjc() {return HdnJvzJgdUtvQtiEceQzk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function VhpSufWorGgmZtvSzoWre(QnkMirRutQprBeuFybSsl){HdnJvzJgdUtvQtiEceQzk[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "return YhdDrqPceKhiNxzEmuBrj - PhkSayMenWuqSuqXnnIcj;};" fullword ascii
    $s6  = "function SucIivFxuHkoFdiVsdXet(YhdDrqPceKhiNxzEmuBrj, PhkSayMenWuqSuqXnnIcj){HavTpeZjcJtvIvfVspZyi = HavTpeZjcJtvIvfVspZyi * 1; " ascii
    $s7  = "var HdnJvzJgdUtvQtiEceQzk = function WbnYcsGhqKumVbeZlvUaa() {return NmvWdlQfeJfxAurHhfQzj[EtlIhnKecDbgQgnAjyOvn](\"WScript\"+\"" ascii
    $s8  = "var NmvWdlQfeJfxAurHhfQzj = this[\"WScript\"];" fullword ascii
    $s9  = "var HdnJvzJgdUtvQtiEceQzk = function WbnYcsGhqKumVbeZlvUaa() {return NmvWdlQfeJfxAurHhfQzj[EtlIhnKecDbgQgnAjyOvn](\"WScript\"+\"" ascii
    $s10 = "function JjxOnkDkfIreUqkMefNjc() {return HdnJvzJgdUtvQtiEceQzk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (BneOaaMwdYozGkcFbpYbv[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function ZueGkkQbyWdmEhzXmfFhm(){return UjoTtyBrqSftLuhHjdXlf + \"\";};" fullword ascii
    $s13 = "function SucIivFxuHkoFdiVsdXet(YhdDrqPceKhiNxzEmuBrj, PhkSayMenWuqSuqXnnIcj){HavTpeZjcJtvIvfVspZyi = HavTpeZjcJtvIvfVspZyi * 1; " ascii
    $s14 = "function KgwEqbTlrTsdHozVikTkp() {return ((GbgIsxCvdSalHpsZrwNyf == true) && (GbgIsxCvdSalHpsZrwNyf == KstNojIowZyaSoeQyxQty)) ?" ascii
    $s15 = "function KgwEqbTlrTsdHozVikTkp() {return ((GbgIsxCvdSalHpsZrwNyf == true) && (GbgIsxCvdSalHpsZrwNyf == KstNojIowZyaSoeQyxQty)) ?" ascii
    $s16 = "function HysXkqZwjRpqIkrDtcXpz(){return EtlIhnKecDbgQgnAjyOvn;};" fullword ascii
    $s17 = "var HiaBhjAdqXalBxxWtbRbn = false;" fullword ascii
    $s18 = "function UteNvcVgrKeoReeMphSqb(WpdRezXmzNhzZkyDjyYgw) {var XkjEdnEioNlpFahAwpVbw = (1, 2, 3, 4, 5, WpdRezXmzNhzZkyDjyYgw); retur" ascii
    $s19 = "function UteNvcVgrKeoReeMphSqb(WpdRezXmzNhzZkyDjyYgw) {var XkjEdnEioNlpFahAwpVbw = (1, 2, 3, 4, 5, WpdRezXmzNhzZkyDjyYgw); retur" ascii
    $s20 = "return SucIivFxuHkoFdiVsdXet(1 == 1 ? VwcZlrSvfIykYzlXyaDfi : 0, 1 == 1 ? GqzChdJgiSyzTezMxkLzu : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}