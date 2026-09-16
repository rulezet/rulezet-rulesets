rule sig_20160311_58aba6f1715eba6a084756b7ba434c2f {
  meta:
    description = "datamaliciousorder - file 20160311_58aba6f1715eba6a084756b7ba434c2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8aad70796b6b7c17755278b311d030bd66e97cdfbe8f20c860c97ff40246dbdb"

  strings:
    $s1  = "var OC = true  , USJm = oUX[7] + oUX[9] + oUX[11];" fullword ascii
    $s2  = "return OctvJdO[0] + OctvJdO[2] + OctvJdO[4] + \".F\" + OctvJdO[7] + OctvJdO[9] + OctvJdO[12] + OctvJdO[14];" fullword ascii
    $s3  = "var OctvJdO = \"Sc ppCvYpC r WxnQrIqVC ipting GADstdR Obu ile AkFGjWseykTsCf System zj KFwpd Obj VCViGs ect nsMPXaZ\".split(\" " ascii
    $s4  = "var oUX = (\"2.XMLHTTP GSdbZTq gqhgs XML ream St cXCtdgTf AD xFsDRYs O zMWo D\").split(\" \");" fullword ascii
    $s5  = "Ttgmb.open(yqlXV,dLvlV,false);" fullword ascii
    $s6  = "function dDCC(mbCHU,DTJwU) {" fullword ascii
    $s7  = "function peQaXVbi(nmLXk,cJSalj) {" fullword ascii
    $s8  = "return dUWdX;" fullword ascii
    $s9  = "function FeEWhWdDC(cqmvnDQVGCI) {" fullword ascii
    $s10 = "function hWIn(sfWcf) {" fullword ascii
    $s11 = "function yTgPXlRp() {" fullword ascii
    $s12 = "function rSgd(Ttgmb,dLvlV,yqlXV) {" fullword ascii
    $s13 = "if (g >= MkJAj.length) {break;}" fullword ascii
    $s14 = "function vWbV(MkJAj) {" fullword ascii
    $s15 = "function qsQjRfBs(Mau) {" fullword ascii
    $s16 = "if(p>=b.length) {break;}" fullword ascii
    $s17 = "function YhcV(CIBkg) {" fullword ascii
    $s18 = "return Tegk.ExpandEnvironmentStrings(kRwsz);" fullword ascii
    $s19 = "function bVDR(hJZfQ,xKPNp) {" fullword ascii
    $s20 = "if (CIBkg > 132175-905){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}