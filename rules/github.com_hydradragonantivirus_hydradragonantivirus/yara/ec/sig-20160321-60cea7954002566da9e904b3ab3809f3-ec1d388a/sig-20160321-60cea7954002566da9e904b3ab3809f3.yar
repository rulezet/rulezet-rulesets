rule sig_20160321_60cea7954002566da9e904b3ab3809f3 {
  meta:
    description = "datamaliciousorder - file 20160321_60cea7954002566da9e904b3ab3809f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55a95fa1a33d2f1a5038e0fb04fce2b9a86c74454f8367c798f9cf5d306b2ec2"

  strings:
    $s1  = "return WScript.CreateObject(exygt);" fullword ascii
    $s2  = "return MtvbwLo[0] + MtvbwLo[2] + MtvbwLo[4] + \".F\" + MtvbwLo[7] + MtvbwLo[9] + MtvbwLo[12] + MtvbwLo[14];" fullword ascii
    $s3  = "var mT = true  , MYQw = chg[7] + chg[9] + chg[11];" fullword ascii
    $s4  = "cosBu.open(tRgSk,IKUjR,false);" fullword ascii
    $s5  = "var MtvbwLo = lvGRx(lAzNFPQtZp+\" \"+\"System hT quOEl Obj YADZWg ect WqkQBeE BVTbP\", \" \");" fullword ascii
    $s6  = "var chg = (\"2.XMLHTTP IoSczZA gQDji XML ream St RbbzKuiC AD lzdSBaK O GhCt D\").split(\" \");" fullword ascii
    $s7  = "function lvGRx(qPQ,WQWGM) {" fullword ascii
    $s8  = "function NVIHaEIr(lFAl) {" fullword ascii
    $s9  = "function yivx(cosBu,IKUjR,tRgSk) {" fullword ascii
    $s10 = "return jXYYqeX(YU,ZsQkT[841-835]+ZsQkT[602-595]+ZsQkT[482-474]);" fullword ascii
    $s11 = "function gBGk(hXiWh) {" fullword ascii
    $s12 = "return OFT.size;" fullword ascii
    $s13 = "function fKnrPaYJA(tpBQM) {" fullword ascii
    $s14 = "if (U >= BaUNI.length) {break;}" fullword ascii
    $s15 = "function vrav(exygt) {" fullword ascii
    $s16 = "return HwJaxb.position=619-619;" fullword ascii
    $s17 = "if(G>=A.length) {break;}" fullword ascii
    $s18 = "function jXYYqeX(zaUf,drxrG) {" fullword ascii
    $s19 = "function RZsICcW(cYpP) {" fullword ascii
    $s20 = "function cEVW(UiJqZ,ymIEA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}