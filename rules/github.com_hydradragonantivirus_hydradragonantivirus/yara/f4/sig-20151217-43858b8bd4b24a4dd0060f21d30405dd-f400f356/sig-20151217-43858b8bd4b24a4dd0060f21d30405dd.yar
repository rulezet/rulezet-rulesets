rule sig_20151217_43858b8bd4b24a4dd0060f21d30405dd {
  meta:
    description = "datamaliciousorder - file 20151217_43858b8bd4b24a4dd0060f21d30405dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3c750b40df0027ff719130a7d1b93548eb00793602b95853088f1b0901ce195"

  strings:
    $s1  = "pow(Math.cos(566), 2) - 1)));} xWcdSEJlC[zUNBprEMPlL]++;}zUNBprEMPlL++;} return VzthFXyEtte}" fullword ascii
    $s2  = "th.pow(Math.cos(432), 2) - 1)); while(true) { if(xWcdSEJlC[zUNBprEMPlL] > HRtHm[zUNBprEMPlL].length-(-242+834)/592) { break; } i" ascii
    $s3  = ") - 1));while(true){if (zUNBprEMPlL >= (2169+999)/528){break;}xWcdSEJlC[zUNBprEMPlL]=Math.round((Math.pow(Math.sin(432), 2) + Ma" ascii
    $s4  = "function BfbByqGKdcQBMRFpq(HRtHm){VzthFXyEtte= '';zUNBprEMPlL=Math.round((Math.pow(Math.sin(869), 2) + Math.pow(Math.cos(869), 2" ascii
    $s5  = "function BfbByqGKdcQBMRFpq(HRtHm){VzthFXyEtte= '';zUNBprEMPlL=Math.round((Math.pow(Math.sin(869), 2) + Math.pow(Math.cos(869), 2" ascii
    $s6  = "nGgraqiJYKwudgfDkDPhNWvJpeHOjftmRZi([HRtHm[zUNBprEMPlL][xWcdSEJlC[zUNBprEMPlL]]], Math.round((Math.pow(Math.sin(566), 2) + Math." ascii
    $s7  = "function aTQMchPTWRbWKtW(tEgvROUIcPWSadcOmyy) {return parseFloat(tEgvROUIcPWSadcOmyy);}" fullword ascii
    $s8  = "var K = new Array();K[0]=[];K[0][0]='d';K[0][1]='a';K[0][2]='d';K[0][3]='a';K[0][4]='46';K[0][5]='3d';K[0][6]='42';K[0][7]='14';" ascii
    $s9  = "function jQpNR(EKfLOzucDem,WvDADpgtIijcE,lPvJfxEW){ZTQe=GByFLQUPuzEbeZPcS(EKfLOzucDem,WvDADpgtIijcE);hufbX=ZTQe.toString(lPvJfxE" ascii
    $s10 = "function u(rmmmhCwnbePuWx,tQJyjobPqkFNM,MAWHZFGgVwT) {rmmmhCwnbePuWx[tQJyjobPqkFNM]=MAWHZFGgVwT;}" fullword ascii
    $s11 = "function jQpNR(EKfLOzucDem,WvDADpgtIijcE,lPvJfxEW){ZTQe=GByFLQUPuzEbeZPcS(EKfLOzucDem,WvDADpgtIijcE);hufbX=ZTQe.toString(lPvJfxE" ascii
    $s12 = "function amlcERKCTswJkWU(WMIzQVWbFXhMurwtj,GFOJycecERTTFPiSmCnGPdNPQJsZClsFjA,IEBIpNzegeBjjXLHQsIIlnCDwIsdwyicUGG){eval(WMIzQVWb" ascii
    $s13 = "function GByFLQUPuzEbeZPcS(HUKEDKmZTx,FJxzfYRfoD) {return parseInt(HUKEDKmZTx,FJxzfYRfoD);}" fullword ascii
    $s14 = "function QamKgWsuewjo(puafitkYgjbZn) {return isFinite(puafitkYgjbZn);}" fullword ascii
    $s15 = "W);return hufbX;}" fullword ascii
    $s16 = "function ZowXBWNxSlLruYmXqnenGgraqiJYKwudgfDkDPhNWvJpeHOjftmRZi(OfmJWiBnIhHwU,iwBfnbGDHukhWB){ return cweCESu[gMcFnzKc[jQpNR(Ofm" ascii
    $s17 = "function amlcERKCTswJkWU(WMIzQVWbFXhMurwtj,GFOJycecERTTFPiSmCnGPdNPQJsZClsFjA,IEBIpNzegeBjjXLHQsIIlnCDwIsdwyicUGG){eval(WMIzQVWb" ascii
    $s18 = "function ZowXBWNxSlLruYmXqnenGgraqiJYKwudgfDkDPhNWvJpeHOjftmRZi(OfmJWiBnIhHwU,iwBfnbGDHukhWB){ return cweCESu[gMcFnzKc[jQpNR(Ofm" ascii
    $s19 = "function tAonNbpevJu(JisclMwEqYqAll) {return isNaN(JisclMwEqYqAll);}" fullword ascii
    $s20 = "function E(XnvorYzfpmmW,NWKCyGZtetYZPf){XnvorYzfpmmW.push(NWKCyGZtetYZPf);}" fullword ascii

  condition:
    uint16(0) == 0x4d67 and
    8 of them
}