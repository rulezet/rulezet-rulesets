rule sig_20160308_2c2a6116b7c30fa3e5bedbe796a4de93 {
  meta:
    description = "datamaliciousorder - file 20160308_2c2a6116b7c30fa3e5bedbe796a4de93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c127a37673d917697a78a9001621fdd110b704643f554432dc4067c7d1342b02"

  strings:
    $s1  = "return nKgTkfO[0] + nKgTkfO[2] + nKgTkfO[4] + \".F\" + nKgTkfO[7] + nKgTkfO[9] + nKgTkfO[12] + nKgTkfO[14];" fullword ascii
    $s2  = "var WC = true  , ydsj = Cip[7] + Cip[9] + Cip[11];" fullword ascii
    $s3  = "var nKgTkfO = \"Sc rtBZdpG r nOsFwfwlU ipting wunqnIv AQT ile fNrSNBNcIswhrK System Di ixYVp Obj VYbKhQ ect ltoAtqM\".split(\" " ascii
    $s4  = "var Cip = (\"2.XMLHTTP LDxzJur VWvin XML ream St JPteyMus AD fiTzLnW O oTON D\").split(\" \");" fullword ascii
    $s5  = "yfCOV.open(KBiYN,fmNLW,false);" fullword ascii
    $s6  = "function NkkcmjjTB(EyKCobkRIni) {" fullword ascii
    $s7  = "return iqfa.responseBody;" fullword ascii
    $s8  = "function PiCKTojO(EhL) {" fullword ascii
    $s9  = "function vozS(TsdNZ) {" fullword ascii
    $s10 = "return Bqhlc;" fullword ascii
    $s11 = "function pQuA(xIVWT,KFiOH) {" fullword ascii
    $s12 = "function qntw(cukeB) {" fullword ascii
    $s13 = "function jbjo(etIZY,snCNu) {" fullword ascii
    $s14 = "if(B>=w.length) {break;}" fullword ascii
    $s15 = "if (((new Date())>0,7655629888)) {" fullword ascii
    $s16 = "function pSDmqIWS() {" fullword ascii
    $s17 = "dYK = B; break; " fullword ascii
    $s18 = "return EhL.size;" fullword ascii
    $s19 = "return mCHBn.status;" fullword ascii
    $s20 = "function EPWJj(oaAjAy) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}