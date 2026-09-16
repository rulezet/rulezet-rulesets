rule sig_20160523_22860873488c17427a164f47f5635082 {
  meta:
    description = "datamaliciousorder - file 20160523_22860873488c17427a164f47f5635082.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84144c832d02b2980773240a742a87a5c5c68ccd2d8b57101959ecc4fdea470a"

  strings:
    $s1  = "function CclsvHbXxx(pghDoLxF,IfTHKerpfbrG) {pghDoLxF.Run(IfTHKerpfbrG, 0x1, 0x0);}" fullword ascii
    $s2  = "function uxhHFxuD(KwfWo) {var iJkvSVsL=DpkTPQByeVCdzJAicPOL[13];for(var kjRow=0;kjRow<KwfWo;kjRow++){qHJoH+=iJkvSVsL.charAt(Math" ascii
    $s3  = "function uxhHFxuD(KwfWo) {var iJkvSVsL=DpkTPQByeVCdzJAicPOL[13];for(var kjRow=0;kjRow<KwfWo;kjRow++){qHJoH+=iJkvSVsL.charAt(Math" ascii
    $s4  = "function HtgPuWO(){return Math.random();}" fullword ascii
    $s5  = "function YqdurJEF(eKorIytwc) {eKorIytwc.type=1;}" fullword ascii
    $s6  = "function Zvuu(PLebrRI,mRHgFay) {PLebrRI.saveToFile(mRHgFay, 2);}" fullword ascii
    $s7  = "function fXOLuEV() {var woLi=100000;var nKXoCj = 100;return HtgPuWO()*(woLi-nKXoCj)+nKXoCj;}" fullword ascii
    $s8  = "function QXZL(hIabZs) {hIabZs.open();}" fullword ascii
    $s9  = "function giJAt(foxAGRdB,pdKUmj,kDbUVaMxJ){mbMmz=foxAGRdB.split(kDbUVaMxJ);yOHtQmR = DpkTPQByeVCdzJAicPOL[12];for(laCSGVun=0;laCS" ascii
    $s10 = "function VlcibJK(dVfka) {dVfka.close();}" fullword ascii
    $s11 = "function WMfQ(QropMX,rzPRhtD){Kcvi = DpkTPQByeVCdzJAicPOL[10].split(DpkTPQByeVCdzJAicPOL[11]);rzPRhtD.open(Kcvi[0]+Kcvi[2]+Kcvi[" ascii
    $s12 = "function WMfQ(QropMX,rzPRhtD){Kcvi = DpkTPQByeVCdzJAicPOL[10].split(DpkTPQByeVCdzJAicPOL[11]);rzPRhtD.open(Kcvi[0]+Kcvi[2]+Kcvi[" ascii
    $s13 = "3], QropMX, false);rzPRhtD.send();}" fullword ascii
    $s14 = "if(TYSr>NXMEo.length) break;" fullword ascii
    $s15 = "function giJAt(foxAGRdB,pdKUmj,kDbUVaMxJ){mbMmz=foxAGRdB.split(kDbUVaMxJ);yOHtQmR = DpkTPQByeVCdzJAicPOL[12];for(laCSGVun=0;laCS" ascii
    $s16 = "function ZnWdnoWIY(klSioF) {var FxkytXkGim=[];klSioF.position=FxkytXkGim.length*(3140146-601);}" fullword ascii
    $s17 = "function VEghi(YHMPTinu,aajdE,bzvsDGzzzE){QXZL(YHMPTinu);YqdurJEF(YHMPTinu);FCmLjdF(YHMPTinu,aajdE);ZnWdnoWIY(YHMPTinu);Zvuu(YHM" ascii
    $s18 = "GVun<pdKUmj.length;laCSGVun++) {yOHtQmR+=mbMmz[pdKUmj[laCSGVun]];}return yOHtQmR.substring(3,yOHtQmR.length);}" fullword ascii
    $s19 = "function DobPDQ(FjsRso){return FjsRso.ExpandEnvironmentStrings(DpkTPQByeVCdzJAicPOL[9])}" fullword ascii
    $s20 = "function FCmLjdF(HOHS,oBxSE) {HOHS.write(oBxSE);}" fullword ascii

  condition:
    uint16(0) == 0x1327 and
    8 of them
}