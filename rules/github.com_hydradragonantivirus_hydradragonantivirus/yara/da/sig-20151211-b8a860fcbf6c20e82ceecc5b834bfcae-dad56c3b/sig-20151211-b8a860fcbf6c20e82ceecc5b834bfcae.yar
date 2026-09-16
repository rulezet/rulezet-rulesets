rule sig_20151211_b8a860fcbf6c20e82ceecc5b834bfcae {
  meta:
    description = "datamaliciousorder - file 20151211_b8a860fcbf6c20e82ceecc5b834bfcae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beb35d32719a772ccf8f9485ece1d3d2e390dc29dbf45b50a3724fecc091fd4c"

  strings:
    $s1  = "function EkfdsTk(uBgzVJUlmczFPhCtugEWXhGMgqJsPrRZClJM) {return !isNaN(parseFloat(uBgzVJUlmczFPhCtugEWXhGMgqJsPrRZClJM)) && isFin" ascii
    $s2  = "function EkfdsTk(uBgzVJUlmczFPhCtugEWXhGMgqJsPrRZClJM) {return !isNaN(parseFloat(uBgzVJUlmczFPhCtugEWXhGMgqJsPrRZClJM)) && isFin" ascii
    $s3  = "function ewpTbHcykMuhsqSBf(JFEhr){ieFtgNkMQHy= '';fNjQjTxNPRa=(-22+22)/951; while(true){if(fNjQjTxNPRa >= (924+940)/932)break;Zl" ascii
    $s4  = " cxPif;}function ixJFpQYTitUvmtF(KqpZvNaMMSevSzqhF){eval(KqpZvNaMMSevSzqhF)}" fullword ascii
    $s5  = "var e=new Array(\"2a\",\"2c\",\"2d\",\"2f\",\"2a\",\"28\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s6  = "function fZSEHCeVlLZMemEErlSARYfFdYTDYfASTBPsHjhpvTTbqMnDRhFUCC(bYQrlHZxWaSar,OrtFsUPYaxnMNm){ return IBaCq[IctEl(bYQrlHZxWaSar[" ascii
    $s7  = "var e=new Array(\"2a\",\"2c\",\"2d\",\"2f\",\"2a\",\"28\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s8  = "var t=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"55\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s9  = ";}fNjQjTxNPRa++;} return ieFtgNkMQHy}" fullword ascii
    $s10 = "var t=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"55\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "LNVawJl[fNjQjTxNPRa]=(-241+241)/952; while(true) { if(ZlLNVawJl[fNjQjTxNPRa] > JFEhr[fNjQjTxNPRa].length-(26+840)/866) { break; " ascii
    $s12 = "function ewpTbHcykMuhsqSBf(JFEhr){ieFtgNkMQHy= '';fNjQjTxNPRa=(-22+22)/951; while(true){if(fNjQjTxNPRa >= (924+940)/932)break;Zl" ascii
    $s13 = "function fZSEHCeVlLZMemEErlSARYfFdYTDYfASTBPsHjhpvTTbqMnDRhFUCC(bYQrlHZxWaSar,OrtFsUPYaxnMNm){ return IBaCq[IctEl(bYQrlHZxWaSar[" ascii
    $s14 = "function zckWVnmUVqN(MaFBdZPa,KOKOPy){return MaFBdZPa.split(KOKOPy)}" fullword ascii
    $s15 = "function IctEl(gNACAAsLJgS,OwNMohBOFJPbH,ipGzFNKT){JpLq=parseInt(gNACAAsLJgS,OwNMohBOFJPbH);cxPif=JpLq.toString(ipGzFNKT);return" ascii
    $s16 = "function IctEl(gNACAAsLJgS,OwNMohBOFJPbH,ipGzFNKT){JpLq=parseInt(gNACAAsLJgS,OwNMohBOFJPbH);cxPif=JpLq.toString(ipGzFNKT);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}