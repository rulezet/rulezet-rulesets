rule sig_20160527_f86f4905640a590ed0bd610fce6784b9 {
  meta:
    description = "datamaliciousorder - file 20160527_f86f4905640a590ed0bd610fce6784b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f59fc7d9b5df49325b40ced96b9d171ac68918b75e705c536c80239d0d2257f6"

  strings:
    $s1  = "function bMLfsBuIsiWb() {return WScript;}function TscDKWT(){return XAhDTfPdu.ExpandEnvironmentStrings(sKWGEhhyophord())}" fullword ascii
    $s2  = "function hPQTxYjklJTfTNWsAUTCQMH(MAdinsjDZr,hbMWGVuWXtrtW){return MAdinsjDZr.charAt(hbMWGVuWXtrtW);}" fullword ascii
    $s3  = "function iOxXRRHZtiarsR(){return wYfXNoIIO(WgXhRxBshea[12],[0,3,6],WgXhRxBshea[13]);}" fullword ascii
    $s4  = "function wYfXNoIIO(JKewkJkoD,Nebqnqz,ZupGqLnPNqjW){kcedXMQz=JKewkJkoD.split(ZupGqLnPNqjW);nrytOkK = WgXhRxBshea[14];for(xdrfUGMF" ascii
    $s5  = "function VZFPciu(hTuWJTAzcNvWL) {var SnPHXhw = LfBTdligvaqkaUBOqufyp.join(WgXhRxBshea[6]);var QDfnJhFb, PdFseDgUgCSDL, WQrHEYyxL" ascii
    $s6  = "var QDQchBkAlUW = hzCqsDcVaOw.createtextfile(XAhDTfPdu.ExpandEnvironmentStrings(WgXhRxBshea[2]+WgXhRxBshea[3])+String.fromCharCo" ascii
    $s7  = "function sKWGEhhyophord(){return wYfXNoIIO(WgXhRxBshea[8],[1,5,7],WgXhRxBshea[9]);}" fullword ascii
    $s8  = "HEYyxLaAMZIiheyLbccXy = ZlsyarWemwjpCdlXiOarC & 0xff;if (ZkSeaNj == 64) CsqURwyiuvxVG += ps(QDfnJhFb);else if (czpeVk == 64) Csq" ascii
    $s9  = "var hzCqsDcVaOw=function(){return new ActiveXObject(WgXhRxBshea[0]);}();" fullword ascii
    $s10 = "LbccXy);} while (AqBllJ < hTuWJTAzcNvWL.length);return CsqURwyiuvxVG;}" fullword ascii
    $s11 = "function hndMaqq(BNqvtpu,kEVQeJewBmwGNRrecQD){return BNqvtpu.indexOf(kEVQeJewBmwGNRrecQD);}" fullword ascii
    $s12 = "function MjJJljD(obTSomLhlqxiiP,auQsWt) {var gqMguzz=[WgXhRxBshea[15]];obTSomLhlqxiiP[gqMguzz[0]](auQsWt,0x1,0x0)}" fullword ascii
    $s13 = "de(92)+WgXhRxBshea[4],true);" fullword ascii
    $s14 = "function aHhLjPpWhELmisk(uxygAekjdfG,hvpqaXnskwyjPiOOVdgvci,mntcfxudgKN){return String.fromCharCode(uxygAekjdfG,hvpqaXnskwyjPiOO" ascii
    $s15 = "function dtUzECx(MGHtahahEkLefmRwVsjxWzpY,nbjZufsDZMwZCFlf){return String.fromCharCode(MGHtahahEkLefmRwVsjxWzpY,nbjZufsDZMwZCFlf" ascii
    $s16 = "function ps(TaxsrmxbtctjHJRQbaJT){return String.fromCharCode(TaxsrmxbtctjHJRQbaJT);}" fullword ascii
    $s17 = "function wYfXNoIIO(JKewkJkoD,Nebqnqz,ZupGqLnPNqjW){kcedXMQz=JKewkJkoD.split(ZupGqLnPNqjW);nrytOkK = WgXhRxBshea[14];for(xdrfUGMF" ascii
    $s18 = "ApWC=0;xdrfUGMFApWC<Nebqnqz.length;xdrfUGMFApWC++) {nrytOkK+=kcedXMQz[Nebqnqz[xdrfUGMFApWC]];}return nrytOkK.substring(3,nrytOkK" ascii
    $s19 = "function NQVWlzvv(){return wYfXNoIIO(WgXhRxBshea[10],[2,4,8,10],WgXhRxBshea[11]);}" fullword ascii
    $s20 = "function VZFPciu(hTuWJTAzcNvWL) {var SnPHXhw = LfBTdligvaqkaUBOqufyp.join(WgXhRxBshea[6]);var QDfnJhFb, PdFseDgUgCSDL, WQrHEYyxL" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}