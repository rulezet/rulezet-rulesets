rule sig_20160524_9544e889686ea046b9b75f9156c5315a {
  meta:
    description = "datamaliciousorder - file 20160524_9544e889686ea046b9b75f9156c5315a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c16dff3ac38a03bf4a38916183af5effb0ff691c1a3533a55062cdbe7c7c40a"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "0\"];oZKkemY.Close();WrNjEy.Run(RvecZQZDyK[0]+gblHZvKmfAY,0x1,0x0);}BzspvAFFz();function (JDKse) {return new ActiveXObject(JDKse" ascii
    $s3  = "lose();}function lchwuzCllm(IxHUjxjD,rdORSGUPXaBc) {IxHUjxjD.Run(rdORSGUPXaBc, 0x1, 0x0);}function ETvOEHP() {var mhzb=100000;va" ascii
    $s4  = "evWiW) + String.fromCharCode(92) + llBavPz;var jHzoJ = function(){return new ActiveXObject(qhCCE(ISNLQhHRimYAHNOZmk[5],[0,2,4],I" ascii
    $s5  = "b>tjGiw.length) break;var FglLUrWLK=tjGiw[JEVb];var llBavPz=ETvOEHP() + ISNLQhHRimYAHNOZmk[2];var oZTwzBkL=403-402;var fgYjevWiW" ascii
    $s6  = "geRSbaolQ.length*(9590256-507);}function Wjbd(FWMUltq,UAQmgJh) {FWMUltq.saveToFile(UAQmgJh, 2);}function ylyIzoe(mnRml) {mnRml.c" ascii
    $s7  = "IKDjozccuMZIrUAlXVjwEnfCeWUoPuGQDEUVLaOOgFUffSrhBMJFKL*/WScript;}function WIISnLDid(VEcaXd) {var XgeRSbaolQ=[];VEcaXd.position=X" ascii
    $s8  = "c=0;dpelc<qwOoe;dpelc++){nOkRn+=mHCaKBik.charAt(Math.floor(Math.random()*mHCaKBik.length));}return nOkRn;}function kLkeeNqfqdpZT" ascii
    $s9  = "LQhHRimYAHNOZmk[11]);GqFYhzR.open(iENx[0]+iENx[2]+iENx[3], BXkqkY, false);GqFYhzR.send();}function qhCCE(plPLEDdl,hQjaDI,BEVrVVP" ascii
    $s10 = "xXCuoLsBJ=function(){return new ActiveXObject(MaLsOjwqakXsbKnljSAsC[0]);}();var WrNjEy=function(){return new ActiveXObject(\"WSc" ascii
    $s11 = "Strings(MaLsOjwqakXsbKnljSAsC[3])+String.fromCharCode(92)+dMghJbmDu;oZKkemY = xXCuoLsBJ.OpenTextFile(gblHZvKmfAY,2,true);oZKkemY" ascii
    $s12 = "SNLQhHRimYAHNOZmk[6]));}();ZkAZ(FglLUrWLK,jHzoJ);if (jHzoJ.status == 100+100) {var BysWfjv = function() {return new ActiveXObjec" ascii
    $s13 = "6a\\x65\\x63\\x74\",\"\\x66\\x79\\x6f\\x47\\x70\\x6c\\x4f\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function Bzs" ascii
    $s14 = "NLQhHRimYAHNOZmk[9])}function XYACl(aHkwnfnM,YNJKS,WXvgybyAKu){aHkwnfnM.open();vrYroZPJ(aHkwnfnM);rXQrDHK(aHkwnfnM,YNJKS);WIISnL" ascii
    $s15 = "ction rXQrDHK(eWEr,BbBbh) {eWEr.write(BbBbh);}function rBfJmcGotT() {return/*DXYVSoLxatTsXQgYjKKhIGqlTIlbNxeVObiMXchRKCobainKsYq" ascii
    $s16 = "nction ZAWKjJA(){return Math.random();}function iARx(gRVsqz) {gRVsqz.open();}function vrYroZPJ(YuZvzhqRo) {YuZvzhqRo.type=1;}fun" ascii
    $s17 = " = function(){return new ActiveXObject(qhCCE(ISNLQhHRimYAHNOZmk[3],[0,2,4],ISNLQhHRimYAHNOZmk[4]));}();var llBavPz = WgFFiS(fgYj" ascii
    $s18 = "m(UdkrqkoYoMDmaB) {return new ActiveXObject(UdkrqkoYoMDmaB);}');var RvecZQZDyK=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65" ascii
    $s19 = "=DgitD[hQjaDI[xqBLjdZr]];}return fMjIeYF.substring(3,fMjIeYF.length);}function cKAMaiopHkRsE() {rBfJmcGotT().Sleep(4990-673);}fu" ascii
    $s20 = "Did(aHkwnfnM);Wjbd(aHkwnfnM,WXvgybyAKu);ylyIzoe(aHkwnfnM);}function ZkAZ(BXkqkY,GqFYhzR){iENx = ISNLQhHRimYAHNOZmk[10].split(ISN" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}