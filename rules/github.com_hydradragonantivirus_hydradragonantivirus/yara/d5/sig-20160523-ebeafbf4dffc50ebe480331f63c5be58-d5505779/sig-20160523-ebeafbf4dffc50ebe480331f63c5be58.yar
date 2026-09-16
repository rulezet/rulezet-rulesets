rule sig_20160523_ebeafbf4dffc50ebe480331f63c5be58 {
  meta:
    description = "datamaliciousorder - file 20160523_ebeafbf4dffc50ebe480331f63c5be58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e04afdf78789a565ade5b74edbd55ed552322fa90a0b0229d203c3a21272c4e"

  strings:
    $s1  = "function EPTykItf(ZAnnM) {var ofHRxbzf=uwzZrvaeJRd[13];for(var aFzVu=0;aFzVu<ZAnnM;aFzVu++){XUdFH+=ofHRxbzf.charAt(Math.floor(Ma" ascii
    $s2  = "function EPTykItf(ZAnnM) {var ofHRxbzf=uwzZrvaeJRd[13];for(var aFzVu=0;aFzVu<ZAnnM;aFzVu++){XUdFH+=ofHRxbzf.charAt(Math.floor(Ma" ascii
    $s3  = "function xqRdhkEweR(bBbBHwii,sNldIDveCAxD) {bBbBHwii.Run(sNldIDveCAxD, 0x1, 0x0);}" fullword ascii
    $s4  = "function pHVeK(JwgMiSkp,fMZIW,jLLHPhPJIx){cNrB(JwgMiSkp);qzQHcceP(JwgMiSkp);JAdibev(JwgMiSkp,fMZIW);lJDzRdGIT(JwgMiSkp);jaIa(Jwg" ascii
    $s5  = "th.random()*ofHRxbzf.length));}return XUdFH;}" fullword ascii
    $s6  = "function jaIa(rXGrvSQ,ZVRyROz) {rXGrvSQ.saveToFile(ZVRyROz, 2);}" fullword ascii
    $s7  = "if(YJhZ>Gigbq.length) break;" fullword ascii
    $s8  = "function Mcus(Ujdeed,ntJjevB){yhWX = uwzZrvaeJRd[10].split(uwzZrvaeJRd[11]);ntJjevB.open(yhWX[0]+yhWX[2]+yhWX[3], Ujdeed, false)" ascii
    $s9  = "function pHVeK(JwgMiSkp,fMZIW,jLLHPhPJIx){cNrB(JwgMiSkp);qzQHcceP(JwgMiSkp);JAdibev(JwgMiSkp,fMZIW);lJDzRdGIT(JwgMiSkp);jaIa(Jwg" ascii
    $s10 = "wx.length;KazbxKQK++) {HZrIenX+=ygQfy[njkswx[KazbxKQK]];}return HZrIenX.substring(3,HZrIenX.length);}" fullword ascii
    $s11 = "function yacLA(hKWNFNmy,njkswx,VGYBYakUz){ygQfy=hKWNFNmy.split(VGYBYakUz);HZrIenX = uwzZrvaeJRd[12];for(KazbxKQK=0;KazbxKQK<njks" ascii
    $s12 = "function qzQHcceP(LpledDLHq) {LpledDLHq.type=1;}" fullword ascii
    $s13 = "function ebHErhW(){return Math.random();}" fullword ascii
    $s14 = "function liajir(wFJVNr){return wFJVNr.ExpandEnvironmentStrings(uwzZrvaeJRd[9])}" fullword ascii
    $s15 = "function lJDzRdGIT(dFmJiE) {var yfqiczawkJ=[];dFmJiE.position=yfqiczawkJ.length*(6428780-380);}" fullword ascii
    $s16 = "function OjbYS(wFJVNr){return new ActiveXObject(wFJVNr);}" fullword ascii
    $s17 = "function yacLA(hKWNFNmy,njkswx,VGYBYakUz){ygQfy=hKWNFNmy.split(VGYBYakUz);HZrIenX = uwzZrvaeJRd[12];for(KazbxKQK=0;KazbxKQK<njks" ascii
    $s18 = "function pjyUzVZ(HQrOR) {HQrOR.close();}" fullword ascii
    $s19 = "function JAdibev(Rvvp,ckXQb) {Rvvp.write(ckXQb);}" fullword ascii
    $s20 = "function cNrB(AYqNxe) {AYqNxe.open();}" fullword ascii

  condition:
    uint16(0) == 0x0327 and
    8 of them
}