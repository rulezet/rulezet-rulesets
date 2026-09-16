rule sig_20160302_d216794dcd493df223967c6ab3c492d8 {
  meta:
    description = "datamaliciousorder - file 20160302_d216794dcd493df223967c6ab3c492d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea63df9023ea79127309028de637140172ca63a5aa53173b57d973f72d2aadce"

  strings:
    $s1  = "var uM = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(CBoOE);" fullword ascii
    $s3  = "var OS = true  , EwGQ = nZf[7] + \"\" + nZf[9];" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + aVnoNaN + \".F\" + DSAnCEWSRa + zOopZ + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "Ggdrq.open(egXed,aDdxY,false);" fullword ascii
    $s6  = "return BPIjx;" fullword ascii
    $s7  = "function ZWXw(XlmnJ) {" fullword ascii
    $s8  = "return BH.ExpandEnvironmentStrings(uM);" fullword ascii
    $s9  = "return new ActiveXObject(GxAfTS);" fullword ascii
    $s10 = "if(d>=y.length) {break;}" fullword ascii
    $s11 = "FhK = d; break; " fullword ascii
    $s12 = "return jkpNe.status;" fullword ascii
    $s13 = "function osdS(jkpNe) {" fullword ascii
    $s14 = "function XXet(HjHYF) {" fullword ascii
    $s15 = "function gcckOUxW() {" fullword ascii
    $s16 = "function LaTk(FDvio) {" fullword ascii
    $s17 = "var nZf = (YBB + \"TTP\" + \" dLCaozo OHAwe XML ream St JhMBALxi AD aUpjYLz OD\").split(\" \");" fullword ascii
    $s18 = "function DBAqU(GxAfTS) {" fullword ascii
    $s19 = "function dmFe(CTnlz,kzdnH) {" fullword ascii
    $s20 = "function BRwo(GdONc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}