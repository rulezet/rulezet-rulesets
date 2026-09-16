rule sig_20151214_a647f2539e67bdf5ae8ee6b1cc606d23 {
  meta:
    description = "datamaliciousorder - file 20151214_a647f2539e67bdf5ae8ee6b1cc606d23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9dfad8cbcc7adb3ad6d57d05a8f9e0506dab8e4cab0c0c0fc4fa98c15120aa06"

  strings:
    $s1  = "ath.pow(Math.cos(900), 2) - 1)); while(true) { if(UrFJmKDEb[krUUJUGwqeS] > xAJyW[krUUJUGwqeS].length-(68+806)/874) { break; } if" ascii
    $s2  = "w(Math.cos(63), 2) - 1)));} UrFJmKDEb[krUUJUGwqeS]++;}} return bXvVPvigQFe}" fullword ascii
    $s3  = "function AZxAEhjdBNdNUNsTH(xAJyW){bXvVPvigQFe= X[1748];for(krUUJUGwqeS=Math.round((Math.pow(Math.sin(336), 2) + Math.pow(Math.co" ascii
    $s4  = "function AZxAEhjdBNdNUNsTH(xAJyW){bXvVPvigQFe= X[1748];for(krUUJUGwqeS=Math.round((Math.pow(Math.sin(336), 2) + Math.pow(Math.co" ascii
    $s5  = "IBjub)) {return (String.fromCharCode(UCvYNhwuNPzIBjub) + String.fromCharCode((40141+47)/788));}}" fullword ascii
    $s6  = "function sh(fwxWpaUNGbhd,OAKaKndGKYHJhF){fwxWpaUNGbhd.push(OAKaKndGKYHJhF);}function Q7(UCvYNhwuNPzIBjub){if(QRZMtnG(UCvYNhwuNPz" ascii
    $s7  = "function QRZMtnG(KaFYxRStevtcOwxpTAgyzIhORdrtMuvcsJsp) {return !isNaN(parseFloat(KaFYxRStevtcOwxpTAgyzIhORdrtMuvcsJsp)) && isFin" ascii
    $s8  = "function QRZMtnG(KaFYxRStevtcOwxpTAgyzIhORdrtMuvcsJsp) {return !isNaN(parseFloat(KaFYxRStevtcOwxpTAgyzIhORdrtMuvcsJsp)) && isFin" ascii
    $s9  = "function ATcVzJHEqFR(dZfcjrtC,ZHSsAH){return dZfcjrtC.split(ZHSsAH)}" fullword ascii
    $s10 = "function tAKFT(WOoPxSHfpMZ,aLgaXNmbYbwje,XDgdzjzc){fqjE=parseInt(WOoPxSHfpMZ,aLgaXNmbYbwje);Ekbrk=fqjE.toString(XDgdzjzc);return" ascii
    $s11 = " Ekbrk;}function PiDMIFzLQKxUGTu(xXPJSEZJEJSkJpFag,IzanSKuhcQIubITGjqVekDjgFOYsiVHfow,mIhSmSgQeSysSezxhaJmAOmcbXQNRmBfabe){eval(" ascii
    $s12 = "function cEmepANwwwQejcPDfSymwiXEdrsutfwFFBxXrtnefTDiIxXtGCUBpc(qImGZOqhgMzSZ,NsfToplqgWzUBa){ return FNRwGSm[LVYpsqaz[tAKFT(qIm" ascii
    $s13 = "var X=new Array();" fullword ascii
    $s14 = "function cEmepANwwwQejcPDfSymwiXEdrsutfwFFBxXrtnefTDiIxXtGCUBpc(qImGZOqhgMzSZ,NsfToplqgWzUBa){ return FNRwGSm[LVYpsqaz[tAKFT(qIm" ascii
    $s15 = "function PiDMIFzLQKxUGTu(xXPJSEZJEJSkJpFag){eval(xXPJSEZJEJSkJpFag)}" fullword ascii
    $s16 = "function sh(fwxWpaUNGbhd,OAKaKndGKYHJhF){fwxWpaUNGbhd.push(OAKaKndGKYHJhF);}function Q7(UCvYNhwuNPzIBjub){if(QRZMtnG(UCvYNhwuNPz" ascii
    $s17 = "function tAKFT(WOoPxSHfpMZ,aLgaXNmbYbwje,XDgdzjzc){fqjE=parseInt(WOoPxSHfpMZ,aLgaXNmbYbwje);Ekbrk=fqjE.toString(XDgdzjzc);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}