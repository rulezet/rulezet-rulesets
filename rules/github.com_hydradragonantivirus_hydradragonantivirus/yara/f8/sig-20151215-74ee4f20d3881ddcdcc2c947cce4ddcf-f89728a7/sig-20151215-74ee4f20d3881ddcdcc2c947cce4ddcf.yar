rule sig_20151215_74ee4f20d3881ddcdcc2c947cce4ddcf {
  meta:
    description = "datamaliciousorder - file 20151215_74ee4f20d3881ddcdcc2c947cce4ddcf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "befc4cbdd6fc67622c1e37be9225118f3666cb1ee0fa0145dcb507bc94062d35"

  strings:
    $s1  = "Math.pow(Math.cos(157), 2) - 1)); while(true) { if(eErYXHoDm[aPZPBLURWlW] > Zxcgc[aPZPBLURWlW].length-(-127+477)/350) { break; }" ascii
    $s2  = "function kbkUCsFEpyXOAIcFj(Zxcgc){CypaandCOKY= N[1754];for(aPZPBLURWlW=Math.round((Math.pow(Math.sin(966), 2) + Math.pow(Math.co" ascii
    $s3  = "pow(Math.cos(225), 2) - 1)));} eErYXHoDm[aPZPBLURWlW]++;}} return CypaandCOKY}" fullword ascii
    $s4  = "DyuRPFsfKmiyGvlCBPamlZYrUDYMOKiKLoV([Zxcgc[aPZPBLURWlW][eErYXHoDm[aPZPBLURWlW]]], Math.round((Math.pow(Math.sin(225), 2) + Math." ascii
    $s5  = "function kbkUCsFEpyXOAIcFj(Zxcgc){CypaandCOKY= N[1754];for(aPZPBLURWlW=Math.round((Math.pow(Math.sin(966), 2) + Math.pow(Math.co" ascii
    $s6  = "function k(wSFBLLCQoPXx,KPsPrARHLMrZSQ){wSFBLLCQoPXx.push(KPsPrARHLMrZSQ);}function E9(tJLXuzSrpIajetXX){if(KQotwqw(tJLXuzSrpIaj" ascii
    $s7  = "etXX)) {return (String.fromCharCode(tJLXuzSrpIajetXX) + String.fromCharCode((56945+151)/936));}}" fullword ascii
    $s8  = "function KQotwqw(LAvFsEcdihOrvqCrfOhsBYjBHtcrAKjIGcqA) {return !isNaN(parseFloat(LAvFsEcdihOrvqCrfOhsBYjBHtcrAKjIGcqA)) && isFin" ascii
    $s9  = "function KQotwqw(LAvFsEcdihOrvqCrfOhsBYjBHtcrAKjIGcqA) {return !isNaN(parseFloat(LAvFsEcdihOrvqCrfOhsBYjBHtcrAKjIGcqA)) && isFin" ascii
    $s10 = "var N=new Array();" fullword ascii
    $s11 = "function sWdtA(IuwNLqlFAzr,AJyNRoTBirWDm,STJflpHv){DzbS=parseInt(IuwNLqlFAzr,AJyNRoTBirWDm);yxUPJ=DzbS.toString(STJflpHv);return" ascii
    $s12 = "function oTUzvHeRWHUUXwTrefVDyuRPFsfKmiyGvlCBPamlZYrUDYMOKiKLoV(GdcCulSnUjCSy,kmJKTFHihQfvTH){ return XgGhmLl[TsCUJpmB[sWdtA(Gdc" ascii
    $s13 = "function NJPOKNvtHaEjbsf(coODbnykLErhzqnfV){eval(coODbnykLErhzqnfV)}" fullword ascii
    $s14 = "function oTUzvHeRWHUUXwTrefVDyuRPFsfKmiyGvlCBPamlZYrUDYMOKiKLoV(GdcCulSnUjCSy,kmJKTFHihQfvTH){ return XgGhmLl[TsCUJpmB[sWdtA(Gdc" ascii
    $s15 = "function sWdtA(IuwNLqlFAzr,AJyNRoTBirWDm,STJflpHv){DzbS=parseInt(IuwNLqlFAzr,AJyNRoTBirWDm);yxUPJ=DzbS.toString(STJflpHv);return" ascii
    $s16 = "function ZwGQvEFBqoq(NYDMOWfQ,NdkVnP){return NYDMOWfQ.split(NdkVnP)}" fullword ascii
    $s17 = " yxUPJ;}function NJPOKNvtHaEjbsf(coODbnykLErhzqnfV,GEClxiimTVgKhDKSCPTrENOSqQJNyKCBBf,QAkzJkhJQNvlSnnxinuVYXqXecFNPfkSgzF){eval(" ascii
    $s18 = "function k(wSFBLLCQoPXx,KPsPrARHLMrZSQ){wSFBLLCQoPXx.push(KPsPrARHLMrZSQ);}function E9(tJLXuzSrpIajetXX){if(KQotwqw(tJLXuzSrpIaj" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}