rule sig_20151211_62f7c19c39922d7875e6ce77f02810be {
  meta:
    description = "datamaliciousorder - file 20151211_62f7c19c39922d7875e6ce77f02810be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3950f4386167c5d98b5e685a052f64dc9f150b72e16b1b7b2190362093f84b1b"

  strings:
    $s1  = "function qYldKJB(cROaGMTihldRbenaKKvIlRFVbbTjSlKrYwRT) {return !isNaN(parseFloat(cROaGMTihldRbenaKKvIlRFVbbTjSlKrYwRT)) && isFin" ascii
    $s2  = "function qYldKJB(cROaGMTihldRbenaKKvIlRFVbbTjSlKrYwRT) {return !isNaN(parseFloat(cROaGMTihldRbenaKKvIlRFVbbTjSlKrYwRT)) && isFin" ascii
    $s3  = "function EdwVTlzXPXbkjtCru(PHNMK){fLXhbNWNDrT= '';ulclvozeXtM=(-629+629)/299; while(true){if(ulclvozeXtM >= (1264+234)/749)break" ascii
    $s4  = "var o=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4d\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s5  = "var o=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4d\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = "]++;}ulclvozeXtM++;} return fLXhbNWNDrT}" fullword ascii
    $s7  = " fATVU;}function VsPpVLKmdOXdanB(FLtJwzoeFyuriNmni){eval(FLtJwzoeFyuriNmni)}" fullword ascii
    $s8  = "function DRuhy(bxKOUeJinnX,kUKtlNmbiyXxB,TeJWBPNd){ufRn=parseInt(bxKOUeJinnX,kUKtlNmbiyXxB);fATVU=ufRn.toString(TeJWBPNd);return" ascii
    $s9  = "function eDnbXbJrwlqkfbUDqhZaLNiUTrQZwEVNNLsDVApqiwcyASLwDbqtsq(OKBcnUFYdZcDr,dlTuHsPkVIHBmY){ return sRRaW[DRuhy(OKBcnUFYdZcDr[" ascii
    $s10 = "function MxPTSJyJxUK(VulCvMTp,hginyV){return VulCvMTp.split(hginyV)}" fullword ascii
    $s11 = "var f=new Array(\"2d\",\"26\",\"26\",\"2e\",\"2f\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s12 = "var f=new Array(\"2d\",\"26\",\"26\",\"2e\",\"2f\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s13 = "function DRuhy(bxKOUeJinnX,kUKtlNmbiyXxB,TeJWBPNd){ufRn=parseInt(bxKOUeJinnX,kUKtlNmbiyXxB);fATVU=ufRn.toString(TeJWBPNd);return" ascii
    $s14 = "function EdwVTlzXPXbkjtCru(PHNMK){fLXhbNWNDrT= '';ulclvozeXtM=(-629+629)/299; while(true){if(ulclvozeXtM >= (1264+234)/749)break" ascii
    $s15 = "function eDnbXbJrwlqkfbUDqhZaLNiUTrQZwEVNNLsDVApqiwcyASLwDbqtsq(OKBcnUFYdZcDr,dlTuHsPkVIHBmY){ return sRRaW[DRuhy(OKBcnUFYdZcDr[" ascii
    $s16 = ";ICSYDMZAO[ulclvozeXtM]=(-821+821)/52; while(true) { if(ICSYDMZAO[ulclvozeXtM] > PHNMK[ulclvozeXtM].length-(-269+320)/51) { brea" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}