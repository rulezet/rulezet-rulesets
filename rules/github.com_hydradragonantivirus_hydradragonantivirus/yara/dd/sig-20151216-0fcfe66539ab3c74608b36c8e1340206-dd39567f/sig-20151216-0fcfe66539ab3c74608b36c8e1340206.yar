rule sig_20151216_0fcfe66539ab3c74608b36c8e1340206 {
  meta:
    description = "datamaliciousorder - file 20151216_0fcfe66539ab3c74608b36c8e1340206.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9d4da01b8f1b783a2f96081927242e8711017e8fd0989b8689e2e82182109cc"

  strings:
    $s1  = "th.pow(Math.cos(139), 2) - 1)); while(true) { if(ZNeVGrDZp[dorDGXjrJNZ] > joNLr[dorDGXjrJNZ].length-(463+5)/468) { break; } if (" ascii
    $s2  = ") - 1));while(true){if (dorDGXjrJNZ >= (4724+268)/832){break;}ZNeVGrDZp[dorDGXjrJNZ]=Math.round((Math.pow(Math.sin(139), 2) + Ma" ascii
    $s3  = "w(Math.cos(544), 2) - 1)));} ZNeVGrDZp[dorDGXjrJNZ]++;}dorDGXjrJNZ++;} return ijNrUtTahDV}" fullword ascii
    $s4  = "function PYXIsgEepCUIwUqWt(joNLr){ijNrUtTahDV= '';dorDGXjrJNZ=Math.round((Math.pow(Math.sin(311), 2) + Math.pow(Math.cos(311), 2" ascii
    $s5  = "function PYXIsgEepCUIwUqWt(joNLr){ijNrUtTahDV= '';dorDGXjrJNZ=Math.round((Math.pow(Math.sin(311), 2) + Math.pow(Math.cos(311), 2" ascii
    $s6  = "function iuOJxRp(aczKfQcJXoOCPJkuiplGeoAwymDpPFMmxTQG) {return !RrXAQADyqBD(FvTevORkVVmyFUL(aczKfQcJXoOCPJkuiplGeoAwymDpPFMmxTQG" ascii
    $s7  = "function vBQZtjmrYmhHgAC(ZFIUkoUfIgqHJChro,kPSLeqBjkmZMrXmQFEeLjfaPlVzOYUAGST,wenHuSyERDxCixFKEWzOGzZPGkcqamhkUdE){eval(ZFIUkoUf" ascii
    $s8  = "var o = new Array();o[0]=[];o[0][0]='d';o[0][1]='a';o[0][2]='d';o[0][3]='a';o[0][4]='46';o[0][5]='3d';o[0][6]='42';o[0][7]='14';" ascii
    $s9  = "function vBQZtjmrYmhHgAC(ZFIUkoUfIgqHJChro,kPSLeqBjkmZMrXmQFEeLjfaPlVzOYUAGST,wenHuSyERDxCixFKEWzOGzZPGkcqamhkUdE){eval(ZFIUkoUf" ascii
    $s10 = "function GJpjRjemnuBvTgcZPGPGLsTUNbWEDvdMKTdymslyfmOcdINQPCRxoS(mlaGDsZDqYCgc,AuxoGreyMRuucS){ return lVCoaoE[PHvOqWQI[TWFIy(mla" ascii
    $s11 = "J);return kyisy;}" fullword ascii
    $s12 = "function TWFIy(RWDGuaLyxQj,IXNSuANNSdSmQ,JFoPHOSJ){eZlE=QpzOkEUPGGBjDTZSD(RWDGuaLyxQj,IXNSuANNSdSmQ);kyisy=eZlE.toString(JFoPHOS" ascii
    $s13 = "function RrXAQADyqBD(vfuZDNhBBNqZkO) {return isNaN(vfuZDNhBBNqZkO);}" fullword ascii
    $s14 = "function iuOJxRp(aczKfQcJXoOCPJkuiplGeoAwymDpPFMmxTQG) {return !RrXAQADyqBD(FvTevORkVVmyFUL(aczKfQcJXoOCPJkuiplGeoAwymDpPFMmxTQG" ascii
    $s15 = "function QpzOkEUPGGBjDTZSD(IlBqBTNTlE,TdRjTiumal) {return parseInt(IlBqBTNTlE,TdRjTiumal);}" fullword ascii
    $s16 = "var o = new Array();o[0]=[];o[0][0]='d';o[0][1]='a';o[0][2]='d';o[0][3]='a';o[0][4]='46';o[0][5]='3d';o[0][6]='42';o[0][7]='14';" ascii
    $s17 = "function GJpjRjemnuBvTgcZPGPGLsTUNbWEDvdMKTdymslyfmOcdINQPCRxoS(mlaGDsZDqYCgc,AuxoGreyMRuucS){ return lVCoaoE[PHvOqWQI[TWFIy(mla" ascii
    $s18 = "function TWFIy(RWDGuaLyxQj,IXNSuANNSdSmQ,JFoPHOSJ){eZlE=QpzOkEUPGGBjDTZSD(RWDGuaLyxQj,IXNSuANNSdSmQ);kyisy=eZlE.toString(JFoPHOS" ascii
    $s19 = "function X(BzpOdsnecqgPpn,JakBNjcVUQOrY,BqGKbNKbkMQ) {BzpOdsnecqgPpn[JakBNjcVUQOrY]=BqGKbNKbkMQ;}" fullword ascii
    $s20 = "function FvTevORkVVmyFUL(jQOyiBnTgHuufhCLgms) {return parseFloat(jQOyiBnTgHuufhCLgms);}" fullword ascii

  condition:
    uint16(0) == 0x4850 and
    8 of them
}