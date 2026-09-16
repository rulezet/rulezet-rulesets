rule sig_20160523_14d2f354631f6120a213498b69cf12c8 {
  meta:
    description = "datamaliciousorder - file 20160523_14d2f354631f6120a213498b69cf12c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b0cc062f4b9e84ecb0161c7efa40fdb61df0e8bdb27607e883b6d77914a0ed6"

  strings:
    $s1  = "function DjPzBxYTxp(qbGXmlHo,bnZlLfIfmyea) {qbGXmlHo.Run(bnZlLfIfmyea, 0x1, 0x0);}" fullword ascii
    $s2  = "function ZAdBZKRK(HxZBP) {var wnbpiMIa=AmRREcXYydsIarqLdZMbBUq[13];for(var QTCKW=0;QTCKW<HxZBP;QTCKW++){jrtqY+=wnbpiMIa.charAt(M" ascii
    $s3  = "function ZAdBZKRK(HxZBP) {var wnbpiMIa=AmRREcXYydsIarqLdZMbBUq[13];for(var QTCKW=0;QTCKW<HxZBP;QTCKW++){jrtqY+=wnbpiMIa.charAt(M" ascii
    $s4  = "ath.floor(Math.random()*wnbpiMIa.length));}return jrtqY;}" fullword ascii
    $s5  = "function GnuUzxwZjw() {return/*pZktbEWCXMDqPBfCAMxtlbkRtVAxeABpfcvDqfddjagVYGtMlHuytmyvakrptLhmWygqGyhBoxSWhVCKTNwcWNrEMDMWILbFU" ascii
    $s6  = "function rIfsLyzH(ZCHZIhNyR) {ZCHZIhNyR.type=1;}" fullword ascii
    $s7  = "function RtRx(vkiOyX,FzDTAcs){vJWf = AmRREcXYydsIarqLdZMbBUq[10].split(AmRREcXYydsIarqLdZMbBUq[11]);FzDTAcs.open(vJWf[0]+vJWf[2]" ascii
    $s8  = "YBEjHju<qoAlfc.length;wYBEjHju++) {wkFrIHz+=intwx[qoAlfc[wYBEjHju]];}return wkFrIHz.substring(3,wkFrIHz.length);}" fullword ascii
    $s9  = "function unRNPcubP(ZeLuiy) {var rjnSZeZZBP=[];ZeLuiy.position=rjnSZeZZBP.length*(6172942-308);}" fullword ascii
    $s10 = "+vJWf[3], vkiOyX, false);FzDTAcs.send();}" fullword ascii
    $s11 = "function qiZAu(IKLNmdtD,yztoW,gPqYwGnFRL){ebpx(IKLNmdtD);rIfsLyzH(IKLNmdtD);zmrXZcv(IKLNmdtD,yztoW);unRNPcubP(IKLNmdtD);mWeG(IKL" ascii
    $s12 = "function HXBbXr(EBdXGG){return EBdXGG.ExpandEnvironmentStrings(AmRREcXYydsIarqLdZMbBUq[9])}" fullword ascii
    $s13 = "function mWeG(zDARTZD,MmZphKc) {zDARTZD.saveToFile(MmZphKc, 2);}" fullword ascii
    $s14 = "function WVpDb(JqgzPEOn,qoAlfc,WqTiDFahA){intwx=JqgzPEOn.split(WqTiDFahA);wkFrIHz = AmRREcXYydsIarqLdZMbBUq[12];for(wYBEjHju=0;w" ascii
    $s15 = "function shvxjAiFZhDOg() {GnuUzxwZjw().Sleep(2427556-738);}" fullword ascii
    $s16 = "function zmrXZcv(UGUp,pGggy) {UGUp.write(pGggy);}" fullword ascii
    $s17 = "function bbwPi(EBdXGG){return new ActiveXObject(EBdXGG);}" fullword ascii
    $s18 = "function qiZAu(IKLNmdtD,yztoW,gPqYwGnFRL){ebpx(IKLNmdtD);rIfsLyzH(IKLNmdtD);zmrXZcv(IKLNmdtD,yztoW);unRNPcubP(IKLNmdtD);mWeG(IKL" ascii
    $s19 = "function WVpDb(JqgzPEOn,qoAlfc,WqTiDFahA){intwx=JqgzPEOn.split(WqTiDFahA);wkFrIHz = AmRREcXYydsIarqLdZMbBUq[12];for(wYBEjHju=0;w" ascii
    $s20 = "function ebpx(fmVZbN) {fmVZbN.open();}" fullword ascii

  condition:
    uint16(0) == 0x0f27 and
    8 of them
}