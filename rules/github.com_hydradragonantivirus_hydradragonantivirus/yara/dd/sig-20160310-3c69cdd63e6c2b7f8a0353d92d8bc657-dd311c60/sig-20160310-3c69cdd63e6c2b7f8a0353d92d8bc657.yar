rule sig_20160310_3c69cdd63e6c2b7f8a0353d92d8bc657 {
  meta:
    description = "datamaliciousorder - file 20160310_3c69cdd63e6c2b7f8a0353d92d8bc657.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "986f71f32f7af3e06205740acb2b42f35514cd20c8dc396923015cc40a82b75d"

  strings:
    $s1  = "var TF = true  , JCiP = jkM[7] + jkM[9] + jkM[11];" fullword ascii
    $s2  = "return sbPHrbO[0] + sbPHrbO[2] + sbPHrbO[4] + \".F\" + sbPHrbO[7] + sbPHrbO[9] + sbPHrbO[12] + sbPHrbO[14];" fullword ascii
    $s3  = "fwGNU.open(GTIeM,qLIFw,false);" fullword ascii
    $s4  = "var sbPHrbO = \"Sc gnNauoH r LBEOhJHSE ipting KPGfzYT Nbg ile FQZdghTSDvphBz System Vz AYkqV Obj ODxYWo ect LHAyJOX\".split(\" " ascii
    $s5  = "var jkM = (\"2.XMLHTTP WwSadoY ahYte XML ream St JyxJCQxL AD ipJYOUK O PuUs D\").split(\" \");" fullword ascii
    $s6  = "return gAdcmlx(DC,SQBtQ[280-274]+SQBtQ[687-680]+SQBtQ[756-748]);" fullword ascii
    $s7  = "return uvgE.responseBody;" fullword ascii
    $s8  = "function cPAZQqRX(QyB) {" fullword ascii
    $s9  = "function DJSXEcFr(JwoAE,DfWUjc) {" fullword ascii
    $s10 = "return orOC.ExpandEnvironmentStrings(UNokW);" fullword ascii
    $s11 = "return dcWPb;" fullword ascii
    $s12 = "function ctBI(hPcKG,ijwRv) {" fullword ascii
    $s13 = "function MptKpFtrl(tInlo,eZqtN,pdNLj,XiLS) {" fullword ascii
    $s14 = "function hHIYXDKi() {" fullword ascii
    $s15 = "exv = V; break; " fullword ascii
    $s16 = "function xQQV(zVEku) {" fullword ascii
    $s17 = "function hCPa(fwGNU,qLIFw,GTIeM) {" fullword ascii
    $s18 = "function nKHk(wvOiF,KpVWC) {" fullword ascii
    $s19 = "function Gkzg(IKdCL) {" fullword ascii
    $s20 = "return QyB.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}