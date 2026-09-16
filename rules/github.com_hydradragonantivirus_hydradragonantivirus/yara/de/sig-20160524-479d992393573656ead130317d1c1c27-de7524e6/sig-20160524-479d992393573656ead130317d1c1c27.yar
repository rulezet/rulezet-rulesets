rule sig_20160524_479d992393573656ead130317d1c1c27 {
  meta:
    description = "datamaliciousorder - file 20160524_479d992393573656ead130317d1c1c27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c52fa0b5934fe37e4d8073ae95d97ef53a347e5ab2474ae9c0d665716675c25"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "{return new ActiveXObject(BmmoS[0]);}();var rXEduEXEIP=function(){return new ActiveXObject(\"WScript.Shell\");}();var chVdnA = B" ascii
    $s3  = "\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x78\\x65\\x20\"];EZzNXHQVP.Close();rXEduEXEIP.Run(FHpojsTL[0]+KsBTfaduiaAbT,0x1,0x0);}EMtek" ascii
    $s4  = "(iULqWGX, 2);}function LerJPPR(WjQyh) {WjQyh.close();}function WsfpIfeSxq(lOVKUCgy,WgKsJYKCYeNP) {lOVKUCgy.Run(WgKsJYKCYeNP, 0x1" ascii
    $s5  = "gomqTFjczuhZjzfKIlCpixvtuBjaDnQQvbQTiIfOAzjGJtabuIccTkooRphSARIqEinPqeVUuYeIcHOLazwiyqaEiyadqPtkHIDf*/WScript;}function DJmBznOU" ascii
    $s6  = "Object(xLBSH(PzrgpkeTrSfAY[3],[0,2,4],PzrgpkeTrSfAY[4]));}();var qZdGNGD = ziLbks(laREpQzIT) + String.fromCharCode(92) + qZdGNGD" ascii
    $s7  = "SeLKWnoH=DEEYy[yfKT];var qZdGNGD=HJYKXJS() + PzrgpkeTrSfAY[2];var MxZODhxg=131-130;var laREpQzIT = function(){return new ActiveX" ascii
    $s8  = "MTPD.send();}function xLBSH(AKyMLGkR,DjYCOJ,pXDafGHyT){SqHjG=AKyMLGkR.split(pXDafGHyT);NhAhFZI = PzrgpkeTrSfAY[12];for(KlVEMcKK=" ascii
    $s9  = "rOrA.open();waZOTJaK(KZZKrOrA);WIniyln(KZZKrOrA,VJenN);DJmBznOUo(KZZKrOrA);zcTo(KZZKrOrA,jshKmLTgro);LerJPPR(KZZKrOrA);}function" ascii
    $s10 = "wIvlWdQDLNU.OpenTextFile(KsBTfaduiaAbT,2,true);EZzNXHQVP.Write('var PzrgpkeTrSfAY=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x73\\x" ascii
    $s11 = "}function ziLbks(reFrRt){return reFrRt.ExpandEnvironmentStrings(PzrgpkeTrSfAY[9])}function whsyd(KZZKrOrA,VJenN,jshKmLTgro){KZZK" ascii
    $s12 = "o(KHfKso) {var oWdIYKinqn=[];KHfKso.position=oWdIYKinqn.length*(5719906-288);}function zcTo(vAMaODB,iULqWGX) {vAMaODB.saveToFile" ascii
    $s13 = "0;KlVEMcKK<DjYCOJ.length;KlVEMcKK++) {NhAhFZI+=SqHjG[DjYCOJ[KlVEMcKK]];}return NhAhFZI.substring(3,NhAhFZI.length);}function rTE" ascii
    $s14 = "h));}return zmdsv;}function dzZRVxJpNcYRla(mUtCpxPtAZGKKx) {return new ActiveXObject(mUtCpxPtAZGKKx);}');var FHpojsTL=[\"\\x77" ascii
    $s15 = "(EdfkK.status == 100+100) {var FPSnFls = function() {return new ActiveXObject(xLBSH(PzrgpkeTrSfAY[7],[0,2,4],PzrgpkeTrSfAY[8]));" ascii
    $s16 = ", 0x0);}function HJYKXJS() {var mfoX=100000;var DkKeHS = 100;return esQHMKg()*(mfoX-DkKeHS)+DkKeHS;}function IGWguuvF(FNCwB) {va" ascii
    $s17 = ";var EdfkK = function(){return new ActiveXObject(xLBSH(PzrgpkeTrSfAY[5],[0,2,4],PzrgpkeTrSfAY[6]));}();JRwF(jSeLKWnoH,EdfkK);if " ascii
    $s18 = " JRwF(pkZRVd,YBoMTPD){gHlC = PzrgpkeTrSfAY[10].split(PzrgpkeTrSfAY[11]);YBoMTPD.open(gHlC[0]+gHlC[2]+gHlC[3], pkZRVd, false);YBo" ascii
    $s19 = "rTEsiQTdppwPz();var DEEYy = [PzrgpkeTrSfAY[0], PzrgpkeTrSfAY[1]];var yfKT=677-677;while(true) {if(yfKT>DEEYy.length) break;var j" ascii
    $s20 = " (mEjxcJSz) {return new ActiveXObject(mEjxcJSz);}" fullword ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}