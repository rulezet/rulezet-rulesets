rule sig_20160405_a7aa99c282497eca33f48a245d591ef8 {
  meta:
    description = "datamaliciousorder - file 20160405_a7aa99c282497eca33f48a245d591ef8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b50a9ffb249cb7196d31af0f07562fae6c0974f7e3341c281c0d5464d278ba1d"

  strings:
    $s1  = "var RR = true  , NBia = sbE[7] + sbE[9] + sbE[11];" fullword ascii
    $s2  = "return uzYgrFd[0] + uzYgrFd[2] + uzYgrFd[4] + \".F\" + uzYgrFd[7] + uzYgrFd[9] + uzYgrFd[12] + uzYgrFd[14];" fullword ascii
    $s3  = "var sbE = (\"2.XMLHTTP oxuLdyk GVNGN XML ream St CPiojHDP AD PhlVVFm O ByyI D\").split(\" \");" fullword ascii
    $s4  = "SQTg.open(YJbOY,fOXiZ,false);" fullword ascii
    $s5  = "if(r>=v.length) {break;}" fullword ascii
    $s6  = "function Ohlj(VTWYB) {" fullword ascii
    $s7  = "function wtIT(ehUcb,yxKPf) {" fullword ascii
    $s8  = "return HHFcC;" fullword ascii
    $s9  = "return \"QInhNvDFYKIThJ\";" fullword ascii
    $s10 = "function AyVt(SOqbJ,DxIgG) {" fullword ascii
    $s11 = "function PMaF(hFTSm) {" fullword ascii
    $s12 = "function ijfe(iTzlT) {" fullword ascii
    $s13 = "function TNBIbPZ(YscM,NzhGz) {" fullword ascii
    $s14 = "return zjQ.size;" fullword ascii
    $s15 = "function BXTs(uIzdP,fOXiZ,YJbOY) {" fullword ascii
    $s16 = "var hzNgOhS = \"uLGOpp*LCl*pt.S\"+\"hell*HXoqsPe*Scri*\";" fullword ascii
    $s17 = "function pGWgO(MHzqRp) {" fullword ascii
    $s18 = "function rCkCLyhOW(RTrsf) {" fullword ascii
    $s19 = "return new ActiveXObject(cPZv);" fullword ascii
    $s20 = "fqv = r; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}