rule sig_20151217_69617d3366de4e26805dbaeb1b1a644c {
  meta:
    description = "datamaliciousorder - file 20151217_69617d3366de4e26805dbaeb1b1a644c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b571519b3c3e461c8e85cf1d65c9031cd35e03a5860d0d0a02cba90c68247205"

  strings:
    $s1  = "ath.cos(862), 2) - 1)));} SGaTGlBqr[JdYadOonToq]++;}JdYadOonToq++;} return xJbSobEAchi}" fullword ascii
    $s2  = "function wikbkkkIvVJvbvwBC(vEbNb){xJbSobEAchi= '';JdYadOonToq=Math.round((Math.pow(Math.sin(9), 2) + Math.pow(Math.cos(9), 2) - " ascii
    $s3  = "function wikbkkkIvVJvbvwBC(vEbNb){xJbSobEAchi= '';JdYadOonToq=Math.round((Math.pow(Math.sin(9), 2) + Math.pow(Math.cos(9), 2) - " ascii
    $s4  = "ow(Math.cos(510), 2) - 1)); while(true) { if(SGaTGlBqr[JdYadOonToq] > vEbNb[JdYadOonToq].length-(-15+324)/309) { break; } if (el" ascii
    $s5  = "1));while(true){if (JdYadOonToq >= (1839+873)/452){break;}SGaTGlBqr[JdYadOonToq]=Math.round((Math.pow(Math.sin(510), 2) + Math.p" ascii
    $s6  = "function elmVKKC(MwmcwYjuyvVinJTTczFkTOGsuERTceiYxoUO) {return !FHgWVrnDGcy(KpzGLplNlTmtDqc(MwmcwYjuyvVinJTTczFkTOGsuERTceiYxoUO" ascii
    $s7  = "var I = new Array();I[0]=[];I[0][0]='d';I[0][1]='a';I[0][2]='d';I[0][3]='a';I[0][4]='46';I[0][5]='3d';I[0][6]='42';I[0][7]='14';" ascii
    $s8  = "function JsXBqVCbIbMK(BmMmCTRUecShk) {return isFinite(BmMmCTRUecShk);}" fullword ascii
    $s9  = "function yjxODylsTjlzchesFzIONvVjSWCjgIIKaVLkmEKeZxCMfzZdcSiIKO(aTmCbgzCEMjpa,BZGhcSVypTcies){ return eddyFNv[JmVrzLOu[gPtYN(aTm" ascii
    $s10 = "function KpzGLplNlTmtDqc(QrymIWrFpdfAhkKOnkr) {return parseFloat(QrymIWrFpdfAhkKOnkr);}" fullword ascii
    $s11 = "function elmVKKC(MwmcwYjuyvVinJTTczFkTOGsuERTceiYxoUO) {return !FHgWVrnDGcy(KpzGLplNlTmtDqc(MwmcwYjuyvVinJTTczFkTOGsuERTceiYxoUO" ascii
    $s12 = "function vfVcchNfiwtHNrrpf(subPnKEJQZ,jNjmxMZEgZ) {return parseInt(subPnKEJQZ,jNjmxMZEgZ);}" fullword ascii
    $s13 = "function FHgWVrnDGcy(kBYEVMJBPUksQI) {return isNaN(kBYEVMJBPUksQI);}" fullword ascii
    $s14 = "function i(gFhOJHZbKpPtzm,eHiXgIJGNIQNf,CrgGRJIAMpv) {gFhOJHZbKpPtzm[eHiXgIJGNIQNf]=CrgGRJIAMpv;}" fullword ascii
    $s15 = "function yjxODylsTjlzchesFzIONvVjSWCjgIIKaVLkmEKeZxCMfzZdcSiIKO(aTmCbgzCEMjpa,BZGhcSVypTcies){ return eddyFNv[JmVrzLOu[gPtYN(aTm" ascii
    $s16 = "function tCVyMHsCKyosjUE(bBfLgWqUlERSCbCoR,uBsVHBxHKTWyvcTnMiqwnhakrhbUKUyApD,XbGPfRAczoAfCSpxStllRAxyQLcPXWGhbMq){eval(bBfLgWqU" ascii
    $s17 = "T);return Mlwhc;}" fullword ascii
    $s18 = "function gPtYN(cJuxrBawPvJ,mBTMEMmyZHKFy,NILAGLtT){Tywv=vfVcchNfiwtHNrrpf(cJuxrBawPvJ,mBTMEMmyZHKFy);Mlwhc=Tywv.toString(NILAGLt" ascii
    $s19 = "function gPtYN(cJuxrBawPvJ,mBTMEMmyZHKFy,NILAGLtT){Tywv=vfVcchNfiwtHNrrpf(cJuxrBawPvJ,mBTMEMmyZHKFy);Mlwhc=Tywv.toString(NILAGLt" ascii
    $s20 = "var I = new Array();I[0]=[];I[0][0]='d';I[0][1]='a';I[0][2]='d';I[0][3]='a';I[0][4]='46';I[0][5]='3d';I[0][6]='42';I[0][7]='14';" ascii

  condition:
    uint16(0) == 0x6d4a and
    8 of them
}