rule sig_20160523_862f5f2383e36a0cac74d88e38e5fc48 {
  meta:
    description = "datamaliciousorder - file 20160523_862f5f2383e36a0cac74d88e38e5fc48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cf8624df82973a64101b09d7efa845d3e384f42c3d9ea571134e64bb39e54b6"

  strings:
    $s1  = "function msAuBeINVf(PVeOwXnX,yxjXwBcHoOEr) {PVeOwXnX.Run(yxjXwBcHoOEr, 0x1, 0x0);}" fullword ascii
    $s2  = "function VfELrCBy(xoVCg) {var nrIJYUdZ=HgzyPRLJWwczvXkIoIJmETk[2];for(var riwuT=0;riwuT<xoVCg;riwuT++){nZKCN+=nrIJYUdZ.charAt(Ma" ascii
    $s3  = "function VfELrCBy(xoVCg) {var nrIJYUdZ=HgzyPRLJWwczvXkIoIJmETk[2];for(var riwuT=0;riwuT<xoVCg;riwuT++){nZKCN+=nrIJYUdZ.charAt(Ma" ascii
    $s4  = "+PScb[3], wrMWWp, false);UQtPLpG.send();}" fullword ascii
    $s5  = "function WcdJzHD(){return Math.random();}" fullword ascii
    $s6  = "function ijSKGlIy(SzGxDsnOZ) {SzGxDsnOZ.type=1;}" fullword ascii
    $s7  = "function Dwku(wrMWWp,UQtPLpG){PScb = HgzyPRLJWwczvXkIoIJmETk[11].split(HgzyPRLJWwczvXkIoIJmETk[12]);UQtPLpG.open(PScb[0]+PScb[2]" ascii
    $s8  = "function HAZQKSl(ptnc,gakEB) {ptnc.write(gakEB);}" fullword ascii
    $s9  = "function fcRDzWQ(hPetl) {hPetl.close();}" fullword ascii
    $s10 = "if (HooBNEn==0) break;" fullword ascii
    $s11 = "function JZkUeal() {var ZLsI=100000;var iQTxad = 100;return WcdJzHD()*(ZLsI-iQTxad)+iQTxad;}" fullword ascii
    $s12 = "UBllxnU<uOZCij.length;SUBllxnU++) {OhLhNNC+=IoYtU[uOZCij[SUBllxnU]];}return OhLhNNC.substring(3,OhLhNNC.length);}" fullword ascii
    $s13 = "function XBUS(ZZOeoyL,lpeVeZv) {ZZOeoyL.saveToFile(lpeVeZv, 2);}" fullword ascii
    $s14 = "th.floor(Math.random()*nrIJYUdZ.length));}return nZKCN;}" fullword ascii
    $s15 = "function eLeGb(NXvbKAsp,uOZCij,yZSLssQSM){IoYtU=NXvbKAsp.split(yZSLssQSM);OhLhNNC = HgzyPRLJWwczvXkIoIJmETk[13];for(SUBllxnU=0;S" ascii
    $s16 = "function eLeGb(NXvbKAsp,uOZCij,yZSLssQSM){IoYtU=NXvbKAsp.split(yZSLssQSM);OhLhNNC = HgzyPRLJWwczvXkIoIJmETk[13];for(SUBllxnU=0;S" ascii
    $s17 = "function VPScv(ygRLNT){return new ActiveXObject(ygRLNT);}" fullword ascii
    $s18 = "try{HooBNEn=gaFUFixji(aPYgN[zxDc], JZkUeal() + HgzyPRLJWwczvXkIoIJmETk[9], 1)}catch(e){}; " fullword ascii
    $s19 = "function vphX(yXmCpC) {yXmCpC.open();}" fullword ascii
    $s20 = "function Dwku(wrMWWp,UQtPLpG){PScb = HgzyPRLJWwczvXkIoIJmETk[11].split(HgzyPRLJWwczvXkIoIJmETk[12]);UQtPLpG.open(PScb[0]+PScb[2]" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}