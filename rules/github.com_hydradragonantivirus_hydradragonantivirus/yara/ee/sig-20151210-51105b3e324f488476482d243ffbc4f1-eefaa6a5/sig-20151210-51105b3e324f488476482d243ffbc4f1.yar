rule sig_20151210_51105b3e324f488476482d243ffbc4f1 {
  meta:
    description = "datamaliciousorder - file 20151210_51105b3e324f488476482d243ffbc4f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "013f6aac379b7d3390653d935303530e1fcf54d62baea128d1b9c4d90ead97f2"

  strings:
    $s1  = "tBEXuPtB[fegrHsikgZc]=(-108+108)/805; while(true) { if(mtBEXuPtB[fegrHsikgZc] > njTMX[fegrHsikgZc].length-(-54+694)/640) { break" ascii
    $s2  = "function qLdNShNXinx(oegCcUSX,KCeRIa){return oegCcUSX.split(KCeRIa)}" fullword ascii
    $s3  = "function FXdYEZfctDNBlXqpMPKzPLJVqpwxLsdVtkGqYBskzGBEbkWjcSJJAY(xYhHSRcuuLSnj,tXDNXunXmExygB){ return yYnvVNoaMzawJ[CLaEn(xYhHSR" ascii
    $s4  = "function YvrMZXKNdLvvhVBtC(njTMX){JowhBwyIYHr= '';for(fegrHsikgZc=(-330+330)/757; fegrHsikgZc < (891+991)/941; fegrHsikgZc++) {m" ascii
    $s5  = "function CLaEn(RPhFKFPWJwn,scyLeZPjORRBi,CGZhzcqP){wGwo=parseInt(RPhFKFPWJwn,scyLeZPjORRBi);ZrDQy=wGwo.toString(CGZhzcqP);return" ascii
    $s6  = "function CLaEn(RPhFKFPWJwn,scyLeZPjORRBi,CGZhzcqP){wGwo=parseInt(RPhFKFPWJwn,scyLeZPjORRBi);ZrDQy=wGwo.toString(CGZhzcqP);return" ascii
    $s7  = "+;}} return JowhBwyIYHr}" fullword ascii
    $s8  = " ZrDQy;}function LlsdQlgDSaIDhdr(cYvsWwmqTJJDaPbGz){eval(cYvsWwmqTJJDaPbGz)}" fullword ascii
    $s9  = "function YvrMZXKNdLvvhVBtC(njTMX){JowhBwyIYHr= '';for(fegrHsikgZc=(-330+330)/757; fegrHsikgZc < (891+991)/941; fegrHsikgZc++) {m" ascii
    $s10 = "lGJxHSm=(-521+521)/702;while(true){if(lGJxHSm>=(106114+638)/834){break;}yYnvVNoaMzawJ[lGJxHSm]=String.fromCharCode(lGJxHSm);lGJx" ascii
    $s11 = "lGJxHSm=(-521+521)/702;while(true){if(lGJxHSm>=(106114+638)/834){break;}yYnvVNoaMzawJ[lGJxHSm]=String.fromCharCode(lGJxHSm);lGJx" ascii
    $s12 = "function FXdYEZfctDNBlXqpMPKzPLJVqpwxLsdVtkGqYBskzGBEbkWjcSJJAY(xYhHSRcuuLSnj,tXDNXunXmExygB){ return yYnvVNoaMzawJ[CLaEn(xYhHSR" ascii
    $s13 = "function eUHaJal(PFxAhcAnqZcoDLiRIGtTGUwXATBcDOVFkxaU) {return !isNaN(parseFloat(PFxAhcAnqZcoDLiRIGtTGUwXATBcDOVFkxaU)) && isFin" ascii
    $s14 = "function eUHaJal(PFxAhcAnqZcoDLiRIGtTGUwXATBcDOVFkxaU) {return !isNaN(parseFloat(PFxAhcAnqZcoDLiRIGtTGUwXATBcDOVFkxaU)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}