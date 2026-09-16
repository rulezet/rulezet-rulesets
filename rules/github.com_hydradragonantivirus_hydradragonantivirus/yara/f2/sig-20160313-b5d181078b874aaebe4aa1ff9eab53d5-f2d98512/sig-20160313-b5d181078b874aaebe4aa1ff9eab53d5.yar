rule sig_20160313_b5d181078b874aaebe4aa1ff9eab53d5 {
  meta:
    description = "datamaliciousorder - file 20160313_b5d181078b874aaebe4aa1ff9eab53d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a94a1e0987b0bb39614e65b982dbefeff684da221d1b7db2f45547537f443db3"

  strings:
    $s1  = "var Xx = true  , tfLr = SFp[7] + SFp[9] + SFp[11];" fullword ascii
    $s2  = "return pTDLtVL[0] + pTDLtVL[2] + pTDLtVL[4] + \".F\" + pTDLtVL[7] + pTDLtVL[9] + pTDLtVL[12] + pTDLtVL[14];" fullword ascii
    $s3  = "rzg.CreateFolder(WHIG);" fullword ascii
    $s4  = "AbLud.open(EwbLM,ERQgM,false);" fullword ascii
    $s5  = "var SFp = (\"2.XMLHTTP eUuEKuv IYHfE XML ream St bpzVWHUG AD zClTiER O XhWL D\").split(\" \");" fullword ascii
    $s6  = "var pTDLtVL = \"Sc kPwtyMM r vvwEDBHyt ipting rMoZzQO lNE ile sZIabSlKCtKlEi System Ua PtCGO Obj sKtMqC ect rVRwfqR\".split(\" " ascii
    $s7  = "return Zje.size;" fullword ascii
    $s8  = "function dmhTLxI(XQlS,bHJEG) {" fullword ascii
    $s9  = "function oKZNd(tfLAwz) {" fullword ascii
    $s10 = "return MAsi.responseBody;" fullword ascii
    $s11 = "function lDDK(JwVwX) {" fullword ascii
    $s12 = "return XQlS.ExpandEnvironmentStrings(bHJEG);" fullword ascii
    $s13 = "return new ActiveXObject(tfLAwz);" fullword ascii
    $s14 = "function KTCtOomY() {" fullword ascii
    $s15 = "return APuyqW.position=721-721;" fullword ascii
    $s16 = "function fNNt(TtFVK) {" fullword ascii
    $s17 = "function LxKi(enEJT) {" fullword ascii
    $s18 = "function qWZW(JEhde) {" fullword ascii
    $s19 = "function bPgZ(dTGqo) {" fullword ascii
    $s20 = "return uvzrCdv" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}