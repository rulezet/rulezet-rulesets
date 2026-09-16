rule sig_20160405_3f40addddb871be3f2c8d267e465d244 {
  meta:
    description = "datamaliciousorder - file 20160405_3f40addddb871be3f2c8d267e465d244.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7206a380fa4ea75a7afcb6a5562cf632cb11ec6e94931fad848c2a293ca43c43"

  strings:
    $s1  = "return rQXAuch[0] + rQXAuch[2] + rQXAuch[4] + \".F\" + rQXAuch[7] + rQXAuch[9] + rQXAuch[12] + rQXAuch[14];" fullword ascii
    $s2  = "var EE = true  , TGBB = Yac[7] + Yac[9] + Yac[11];" fullword ascii
    $s3  = "GEOf.open(vKRGq,goYqN,false);" fullword ascii
    $s4  = "var Yac = (\"2.XMLHTTP EkPaVnE AyzYF XML ream St ivySswxY AD cuERszl O nZzQ D\").split(\" \");" fullword ascii
    $s5  = "function lBDTnYw(XowO,kBsVj) {" fullword ascii
    $s6  = "return GDUai;" fullword ascii
    $s7  = "return tHr.size;" fullword ascii
    $s8  = "function zxdF(yWwwV) {" fullword ascii
    $s9  = "if (q >= OoxrT.length) {break;}" fullword ascii
    $s10 = "var hpxUnmf = \"zvPxKQ*WEY*pt.S\"+\"hell*LNlmZNK*Scri*\";" fullword ascii
    $s11 = "function nGGioi(XmZbSoN) {" fullword ascii
    $s12 = "function qyiL(fDGDv,frnwD) {" fullword ascii
    $s13 = "function kVOT(cuNMf,goYqN,vKRGq) {" fullword ascii
    $s14 = "function zacxrNHWx(aBZwDgiNAZN) {" fullword ascii
    $s15 = "function MrdL(osxcB) {" fullword ascii
    $s16 = "return JqMsi.status;" fullword ascii
    $s17 = "function afrN(JqMsi) {" fullword ascii
    $s18 = "return new ActiveXObject(iDSm);" fullword ascii
    $s19 = "function XbJB(OoxrT) {" fullword ascii
    $s20 = "function LVhlQSbQ(tHr) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}