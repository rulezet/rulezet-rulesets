rule sig_20160411_de7fd8343b73371b6b44ae53e267c19f {
  meta:
    description = "datamaliciousorder - file 20160411_de7fd8343b73371b6b44ae53e267c19f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4956b5042937b8e64f335ef361edf52be77afc83cc5cd2e8b8e20d6194f49d2c"

  strings:
    $s1  = "return HIJPgVg[0] + HIJPgVg[2] + HIJPgVg[4] + \".F\" + HIJPgVg[7] + HIJPgVg[9] + HIJPgVg[12] + HIJPgVg[14];" fullword ascii
    $s2  = "var Ug = true  , DwEo = wSp[7] + wSp[9] + wSp[11];" fullword ascii
    $s3  = "xciN.open(PPhpi,TZhTD,false);" fullword ascii
    $s4  = "var wSp = (\"2.XMLHTTP QbyOaQu NDoZa XML ream St QJeEasWH AD WXZLwbc O RRLD D\").split(\" \");" fullword ascii
    $s5  = "if(j>=g.length) {break;}" fullword ascii
    $s6  = "function ATsl(VfLCR) {" fullword ascii
    $s7  = "function xpqN(ldpfk) {" fullword ascii
    $s8  = "function vhdSO(ahlbAY) {" fullword ascii
    $s9  = "return \"arFScGguwTfrRn\";" fullword ascii
    $s10 = "function JuPv(ACiPk) {" fullword ascii
    $s11 = "function tvEz(detaz,IzjCu) {" fullword ascii
    $s12 = "if (h >= vgimM.length) {break;}" fullword ascii
    $s13 = "return RLP.size;" fullword ascii
    $s14 = "function Ztmo(qoqtg) {" fullword ascii
    $s15 = "return ahlbAY[tRRb[166-166]]=141-141;" fullword ascii
    $s16 = "function WGIEjj(VRVh,YOkOdR) {" fullword ascii
    $s17 = "return qmDXp;" fullword ascii
    $s18 = "function kBgJZ(EGtdQzVU,kokO) {" fullword ascii
    $s19 = "function HHANNmM(AuRO) {" fullword ascii
    $s20 = "function aoyx(DrvNM,TZhTD,PPhpi) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}