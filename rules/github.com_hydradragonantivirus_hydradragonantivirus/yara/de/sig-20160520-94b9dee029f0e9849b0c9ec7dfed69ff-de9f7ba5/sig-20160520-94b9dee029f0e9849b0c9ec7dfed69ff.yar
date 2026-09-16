rule sig_20160520_94b9dee029f0e9849b0c9ec7dfed69ff {
  meta:
    description = "datamaliciousorder - file 20160520_94b9dee029f0e9849b0c9ec7dfed69ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0373002896aee155235c63b5deb7756619b19efc27932a5c7dafa589c046e3e3"

  strings:
    $s1  = "function cmTXsuwb(PIDke) {var uLDywTLH=EojezgZ[2];for(var fzNQn=0;fzNQn<PIDke;fzNQn++){CoMnA+=uLDywTLH.charAt(Math.floor(Math.ra" ascii
    $s2  = "function cmTXsuwb(PIDke) {var uLDywTLH=EojezgZ[2];for(var fzNQn=0;fzNQn<PIDke;fzNQn++){CoMnA+=uLDywTLH.charAt(Math.floor(Math.ra" ascii
    $s3  = "ndom()*uLDywTLH.length));}return CoMnA;}" fullword ascii
    $s4  = "function FEDCoM(vgielh){return vgielh.ExpandEnvironmentStrings(EojezgZ[10])}" fullword ascii
    $s5  = "try{FZnLyQn=EhHAeDlZw(asxic[TevB], PsvsooB() + EojezgZ[9], 1)}catch(e){}; " fullword ascii
    $s6  = "function CfNun(BYaFEnkq,FdfEv,tpitISnqSu){BYaFEnkq.open();BYaFEnkq.type = 1;BYaFEnkq.write(FdfEv);BYaFEnkq.position = 0;BYaFEnkq" ascii
    $s7  = "function dxixf(vgielh){return new ActiveXObject(vgielh);}" fullword ascii
    $s8  = "function ZBDzC(LIBoYdCQ,agcldI,YfScPDFfA){Nlndw=LIBoYdCQ.split(YfScPDFfA);YyXHmdc = EojezgZ[13];for(jaiDcqfV=0;jaiDcqfV<agcldI.l" ascii
    $s9  = "function EFya(sdyopc,ppGuWJd){xSAR = EojezgZ[11].split(EojezgZ[12]);ppGuWJd.open(xSAR[0]+xSAR[2]+xSAR[3], sdyopc, false);ppGuWJd" ascii
    $s10 = "ength;jaiDcqfV++) {YyXHmdc+=Nlndw[agcldI[jaiDcqfV]];}return YyXHmdc.substring(3,YyXHmdc.length);}" fullword ascii
    $s11 = "function PsvsooB() {var sUzv=100000;var clIsUu = 100;return Math.random()*(sUzv-clIsUu)+clIsUu;}" fullword ascii
    $s12 = "if (FZnLyQn==0) break;" fullword ascii
    $s13 = "function CfNun(BYaFEnkq,FdfEv,tpitISnqSu){BYaFEnkq.open();BYaFEnkq.type = 1;BYaFEnkq.write(FdfEv);BYaFEnkq.position = 0;BYaFEnkq" ascii
    $s14 = "function ZBDzC(LIBoYdCQ,agcldI,YfScPDFfA){Nlndw=LIBoYdCQ.split(YfScPDFfA);YyXHmdc = EojezgZ[13];for(jaiDcqfV=0;jaiDcqfV<agcldI.l" ascii
    $s15 = "function EFya(sdyopc,ppGuWJd){xSAR = EojezgZ[11].split(EojezgZ[12]);ppGuWJd.open(xSAR[0]+xSAR[2]+xSAR[3], sdyopc, false);ppGuWJd" ascii
    $s16 = "function EhHAeDlZw(CTczacAVJ,KCYJcbI,FQoxBmhp){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}