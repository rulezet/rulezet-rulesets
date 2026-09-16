rule sig_20151217_53622f9f3ef3e1587184d3e34c2c5c8d {
  meta:
    description = "datamaliciousorder - file 20151217_53622f9f3ef3e1587184d3e34c2c5c8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "871382cef470e5dbeef659c989c863a58794ad604a15792f99b39c71b65a3614"

  strings:
    $s1  = "th.pow(Math.cos(122), 2) - 1)); while(true) { if(oPLQQqfFs[mvByWlOAcOX] > yTVMy[mvByWlOAcOX].length-(-73+170)/97) { break; } if " ascii
    $s2  = "ow(Math.cos(449), 2) - 1)));} oPLQQqfFs[mvByWlOAcOX]++;}mvByWlOAcOX++;} return CXzJDGIpwLC}" fullword ascii
    $s3  = ") - 1));while(true){if (mvByWlOAcOX >= (4070+418)/748){break;}oPLQQqfFs[mvByWlOAcOX]=Math.round((Math.pow(Math.sin(122), 2) + Ma" ascii
    $s4  = "function xQoSEZCZvQlNgRRkk(yTVMy){CXzJDGIpwLC= '';mvByWlOAcOX=Math.round((Math.pow(Math.sin(164), 2) + Math.pow(Math.cos(164), 2" ascii
    $s5  = "function xQoSEZCZvQlNgRRkk(yTVMy){CXzJDGIpwLC= '';mvByWlOAcOX=Math.round((Math.pow(Math.sin(164), 2) + Math.pow(Math.cos(164), 2" ascii
    $s6  = "function rHStctG(uTMwNeWHpeBGtTxDOVceQlVgmDukaIkdhUiI) {return !ACHmHgLDSDA(lwbJQtBBPkngSMd(uTMwNeWHpeBGtTxDOVceQlVgmDukaIkdhUiI" ascii
    $s7  = "var H = new Array();H[0]=[];H[0][0]='d';H[0][1]='a';H[0][2]='d';H[0][3]='a';H[0][4]='46';H[0][5]='3d';H[0][6]='42';H[0][7]='14';" ascii
    $s8  = "function c(CbhHypuNGtHY,vjuEykqfXQBZOA){CbhHypuNGtHY.push(vjuEykqfXQBZOA);}" fullword ascii
    $s9  = "var H = new Array();H[0]=[];H[0][0]='d';H[0][1]='a';H[0][2]='d';H[0][3]='a';H[0][4]='46';H[0][5]='3d';H[0][6]='42';H[0][7]='14';" ascii
    $s10 = "function rHStctG(uTMwNeWHpeBGtTxDOVceQlVgmDukaIkdhUiI) {return !ACHmHgLDSDA(lwbJQtBBPkngSMd(uTMwNeWHpeBGtTxDOVceQlVgmDukaIkdhUiI" ascii
    $s11 = "function U(pRFMlzypVBqaVa,DdgrxiUQYTday,MvAEtQVVfkX) {pRFMlzypVBqaVa[DdgrxiUQYTday]=MvAEtQVVfkX;}" fullword ascii
    $s12 = "function aaZWxdZhbNFfrfq(ecyKVOxFMJCWSVoCB,AXmCXBUKAwahYKjmXePPmfLIjXYhIHctNZ,jRckNMvlsssSDJJSGskeNtVmPknprdWLncm){eval(ecyKVOxF" ascii
    $s13 = "function GrfGb(qFglfAHEuvs,FBxnxDZWEJUYo,xOwHrrOV){kMWJ=XSYvFTeHGQDUdVxoI(qFglfAHEuvs,FBxnxDZWEJUYo);YMrVu=kMWJ.toString(xOwHrrO" ascii
    $s14 = "function ACHmHgLDSDA(dgznfhCbPxPFyo) {return isNaN(dgznfhCbPxPFyo);}" fullword ascii
    $s15 = "function lwbJQtBBPkngSMd(lrvrGeScVkdfjFjdKwp) {return parseFloat(lrvrGeScVkdfjFjdKwp);}" fullword ascii
    $s16 = "function aaZWxdZhbNFfrfq(ecyKVOxFMJCWSVoCB,AXmCXBUKAwahYKjmXePPmfLIjXYhIHctNZ,jRckNMvlsssSDJJSGskeNtVmPknprdWLncm){eval(ecyKVOxF" ascii
    $s17 = "V);return YMrVu;}" fullword ascii
    $s18 = "function apqtVrNTuPrG(ghfygcIuCCOYB) {return isFinite(ghfygcIuCCOYB);}" fullword ascii
    $s19 = "function GrfGb(qFglfAHEuvs,FBxnxDZWEJUYo,xOwHrrOV){kMWJ=XSYvFTeHGQDUdVxoI(qFglfAHEuvs,FBxnxDZWEJUYo);YMrVu=kMWJ.toString(xOwHrrO" ascii
    $s20 = "function XSYvFTeHGQDUdVxoI(jktFQZRbTl,BNdJapZRFp) {return parseInt(jktFQZRbTl,BNdJapZRFp);}" fullword ascii

  condition:
    uint16(0) == 0x7775 and
    8 of them
}