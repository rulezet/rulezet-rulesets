rule sig_20160404_b36489842c937af36a92d86f7ded5f24 {
  meta:
    description = "datamaliciousorder - file 20160404_b36489842c937af36a92d86f7ded5f24.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7451cf45ffb0a993cb0029b4d44c3c9ae3eb91aa122158f26ac5e8e5fb9ae66"

  strings:
    $s1  = "var yb = true  , cKHT = dzq[7] + dzq[9] + dzq[11];" fullword ascii
    $s2  = "return ftZdNBt[0] + ftZdNBt[2] + ftZdNBt[4] + \".F\" + ftZdNBt[7] + ftZdNBt[9] + ftZdNBt[12] + ftZdNBt[14];" fullword ascii
    $s3  = "var dzq = (\"2.XMLHTTP meXuTAy uBaqg XML ream St VjrdOZpV AD QubgWuw O qvaF D\").split(\" \");" fullword ascii
    $s4  = "var ftZdNBt = rARfM(EAgPHxMnMd+\" \"+\"System vr boJbZ Obj UZkRpT ect xGrqZaN CdDnE\", \" \");" fullword ascii
    $s5  = "GbEm.open(qyfPB,PQSjm,false);" fullword ascii
    $s6  = "function huCi(dDJxH) {" fullword ascii
    $s7  = "function FswahaFLG(HtxdjMAbZYs) {" fullword ascii
    $s8  = "function BKGyUC(NzmMThO) {" fullword ascii
    $s9  = "function kLoh(JRZLu) {" fullword ascii
    $s10 = "function VEBQ(kKzoK) {" fullword ascii
    $s11 = "function NwlB(ZQTMO) {" fullword ascii
    $s12 = "if(l>=C.length) {break;}" fullword ascii
    $s13 = "function wBBfdJfa(BAIn) {" fullword ascii
    $s14 = "var tYmRVns = \"CscTYJ*YlC*pt.S\"+\"hell*xuqQqSu*Scri*\";" fullword ascii
    $s15 = "return CJsA[USYZpp[0]];" fullword ascii
    $s16 = "return new ActiveXObject(njyO);" fullword ascii
    $s17 = "function HQcr(cOFVC,JIutW) {" fullword ascii
    $s18 = "function uJxNTo(wHqR,vFXKWa) {" fullword ascii
    $s19 = "return amNTmDC(cP,VEAPL[651-645]+VEAPL[316-309]+VEAPL[933-925]);" fullword ascii
    $s20 = "function aUja(BrplR) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}