rule sig_20160531_8753303d26f5f081e3fd635403caa7ed {
  meta:
    description = "datamaliciousorder - file 20160531_8753303d26f5f081e3fd635403caa7ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b631ab64710ad667a5f38d5093c6df40f64eb0cda581b15199d5137ba921435d"

  strings:
    $s1  = "var NDutbHfGro=function(){return WScript.CreateObject(HyAKnNDuhefYGtnKxP[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function vdbTSqesPy(QbMyLgHqFpLQW) {var zNjWSpyGEIImEqXOlMKfyuDB = eHainAQBmM.join(HyAKnNDuhefYGtnKxP[7]);var DFlgHzsenguTNsKlIa" ascii
    $s3  = "function iaVJEMSkcHIUBLEHpDaarB(vaWFgbsrm,usxfitxjMsGxqwwEJMiXMp){return vaWFgbsrm.charAt(usxfitxjMsGxqwwEJMiXMp);}" fullword ascii
    $s4  = "function vdbTSqesPy(QbMyLgHqFpLQW) {var zNjWSpyGEIImEqXOlMKfyuDB = eHainAQBmM.join(HyAKnNDuhefYGtnKxP[7]);var DFlgHzsenguTNsKlIa" ascii
    $s5  = "(fgrKqILoRQo,0x1,0x0)}function kwLws(aWHtDoGKYol,AVvCmXKDeHzIOR,qTtDbxNZ){var TXMwTTWqbRiZz=aWHtDoGKYol.createtextfile(AVvCmXKDe" ascii
    $s6  = "function tJdPWP(mBnwXiA,fgrKqILoRQo) {var BzGOFLxegXsN=[HyAKnNDuhefYGtnKxP[15]];mBnwXiA[BzGOFLxegXsN[0]]" fullword ascii
    $s7  = "function znsWOjYBKuw(ITHgYRqfYxkoc,cxobIxxFtwfTC,iDoxv){DqPeKyxDgtC=ITHgYRqfYxkoc.split(iDoxv);hFshaFt = HyAKnNDuhefYGtnKxP[0];f" ascii
    $s8  = "function YjwgIB(){return NDutbHfGro.ExpandEnvironmentStrings(ccZBumPFMwoyZn())}" fullword ascii
    $s9  = "function hrjqB(FYpuvlnH,qgBFicL,aqUXxrVTAigQOs){return String.fromCharCode(FYpuvlnH,qgBFicL,aqUXxrVTAigQOs);}" fullword ascii
    $s10 = "sKlIaFcpd, YAFpWQNJ);else BLbqmgwcPGvYewpeRYOtxqAP += hrjqB(DFlgHzsenguTNsKlIaFcpd, YAFpWQNJ, prIoHpolXWVizF);} while (joteQxZQJ" ascii
    $s11 = "function arksxjApQmaPe(ptepkuOlLVfhjpkQDx,WoDPXfEz){return String.fromCharCode(ptepkuOlLVfhjpkQDx,WoDPXfEz);}" fullword ascii
    $s12 = "(fgrKqILoRQo,0x1,0x0)}function kwLws(aWHtDoGKYol,AVvCmXKDeHzIOR,qTtDbxNZ){var TXMwTTWqbRiZz=aWHtDoGKYol.createtextfile(AVvCmXKDe" ascii
    $s13 = "AP += wI(DFlgHzsenguTNsKlIaFcpd);else if (vNBxUiMBSlEVivhPdGUnBCV == 64) BLbqmgwcPGvYewpeRYOtxqAP += arksxjApQmaPe(DFlgHzsenguTN" ascii
    $s14 = "function ZWKVyyXwzNAuTGdOdVoCpUvG(RQpTbLJx,jmoNJUUrScmGtYhBcWtLMP){return RQpTbLJx.indexOf(jmoNJUUrScmGtYhBcWtLMP);}" fullword ascii
    $s15 = "HzIOR,true);TXMwTTWqbRiZz.WriteLine(qTtDbxNZ);TXMwTTWqbRiZz.Close();}" fullword ascii
    $s16 = "function EefbcGp(){return znsWOjYBKuw(HyAKnNDuhefYGtnKxP[13],[0,3,6],HyAKnNDuhefYGtnKxP[14]);}" fullword ascii
    $s17 = "push(\"K\");eHainAQBmM.push(\"L\");eHainAQBmM.push(\"a\");eHainAQBmM.push(\"b\");eHainAQBmM.push(\"c\");eHainAQBmM.push(\"P\");e" ascii
    $s18 = "function ccZBumPFMwoyZn(){return znsWOjYBKuw(HyAKnNDuhefYGtnKxP[9],[1,5,7],HyAKnNDuhefYGtnKxP[10]);}" fullword ascii
    $s19 = "function NijNhiTMXw(){return znsWOjYBKuw(HyAKnNDuhefYGtnKxP[11],[2,4,8,10],HyAKnNDuhefYGtnKxP[12]);}" fullword ascii
    $s20 = "function znsWOjYBKuw(ITHgYRqfYxkoc,cxobIxxFtwfTC,iDoxv){DqPeKyxDgtC=ITHgYRqfYxkoc.split(iDoxv);hFshaFt = HyAKnNDuhefYGtnKxP[0];f" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}