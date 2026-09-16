rule sig_20151209_3f3870357e54b73168039caae2c060fb {
  meta:
    description = "datamaliciousorder - file 20151209_3f3870357e54b73168039caae2c060fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb90aab3464d9305aa5d62377e2001ced2dad61b60e5374428dff4ef636be8e7"

  strings:
    $s1  = "function bWVdUFd(GQvweAzUIGFIasryUsJgwEBsuLkJdZadYHOH) {return !isNaN(parseFloat(GQvweAzUIGFIasryUsJgwEBsuLkJdZadYHOH)) && isFin" ascii
    $s2  = "function bWVdUFd(GQvweAzUIGFIasryUsJgwEBsuLkJdZadYHOH) {return !isNaN(parseFloat(GQvweAzUIGFIasryUsJgwEBsuLkJdZadYHOH)) && isFin" ascii
    $s3  = " xHsTQ;}function bjXedsMkvCVeXAx(ymtfiRSyirHLoHxHl){eval(ymtfiRSyirHLoHxHl)}" fullword ascii
    $s4  = "oMqIKjiI[uEGIgnMdBXL]=(-442+442)/78; while(true) { if(uoMqIKjiI[uEGIgnMdBXL] > dJFHn[uEGIgnMdBXL].length-(-141+982)/841) { break" ascii
    $s5  = "function kRjsskJdAmwIQQBtv(dJFHn){wrEsDAEsXhC= '';for(uEGIgnMdBXL=(-907+907)/447; uEGIgnMdBXL < (941+783)/862; uEGIgnMdBXL++) {u" ascii
    $s6  = ";}} return wrEsDAEsXhC}" fullword ascii
    $s7  = "function YXCYhvhWzNd(imTLQsmn,bMNdjl){return imTLQsmn.split(bMNdjl)}" fullword ascii
    $s8  = "function axfgq(DZaxwSHFHPT,IjbcKeRvByvoT,wFVZESKw){tqwn=parseInt(DZaxwSHFHPT,IjbcKeRvByvoT);xHsTQ=tqwn.toString(wFVZESKw);return" ascii
    $s9  = "function axfgq(DZaxwSHFHPT,IjbcKeRvByvoT,wFVZESKw){tqwn=parseInt(DZaxwSHFHPT,IjbcKeRvByvoT);xHsTQ=tqwn.toString(wFVZESKw);return" ascii
    $s10 = "function BcAZDzukWTZpxogHXWUFXOMvrSJbCOBFXeysPQhYUODfQggoFhIiCD(XzNXbSYZjMdpN,DiPPavZHmtxzCV){ return ssOcp[axfgq(XzNXbSYZjMdpN[" ascii
    $s11 = "function BcAZDzukWTZpxogHXWUFXOMvrSJbCOBFXeysPQhYUODfQggoFhIiCD(XzNXbSYZjMdpN,DiPPavZHmtxzCV){ return ssOcp[axfgq(XzNXbSYZjMdpN[" ascii
    $s12 = "function kRjsskJdAmwIQQBtv(dJFHn){wrEsDAEsXhC= '';for(uEGIgnMdBXL=(-907+907)/447; uEGIgnMdBXL < (941+783)/862; uEGIgnMdBXL++) {u" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}