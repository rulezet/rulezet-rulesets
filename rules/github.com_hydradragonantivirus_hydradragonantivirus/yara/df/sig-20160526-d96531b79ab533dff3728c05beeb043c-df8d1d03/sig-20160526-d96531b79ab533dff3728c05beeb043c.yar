rule sig_20160526_d96531b79ab533dff3728c05beeb043c {
  meta:
    description = "datamaliciousorder - file 20160526_d96531b79ab533dff3728c05beeb043c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7cdc2863fccc330f77e7547fbf18e9ff29b3551b0c76f4d65129f76e108c103"

  strings:
    $s1  = "h.pow(Math.sin(403), 2) + Math.pow(Math.cos(403), 2) - 1))-631)) bctJFuoeKUOYFR += H(YeWZQAvBvYgdCYgVMufsRu);else if (kjLTk == (" ascii
    $s2  = "function UTbtctlikeTmc(YscYkaNzLuqWv) {var enWYBiqBEHdww = BfrooXjVlZkZAEJZjvnDNay.join(KGbywraPyfBVodMRQcFtTaOV[0]);var YeWZQAv" ascii
    $s3  = "function MEdNiZDyNRZWjMxTbeKUDtj(tkzxwQuDuGSqXhmmTsFAGzt,nyUqKtzPsjfhBmNrOX){return tkzxwQuDuGSqXhmmTsFAGzt.charAt(nyUqKtzPsjfhB" ascii
    $s4  = "function MEdNiZDyNRZWjMxTbeKUDtj(tkzxwQuDuGSqXhmmTsFAGzt,nyUqKtzPsjfhBmNrOX){return tkzxwQuDuGSqXhmmTsFAGzt.charAt(nyUqKtzPsjfhB" ascii
    $s5  = "function wDKHBKjlKiXHN(VJKWpsopTlSErFEIWepvP,GytNVoyYwsJleEJgy,LbBcpaLTtFoBZoTfmSrrRo){return String.fromCharCode(VJKWpsopTlSErF" ascii
    $s6  = "function H(FTYrxJRkJPdNtJOpaoYRF){return String.fromCharCode(FTYrxJRkJPdNtJOpaoYRF);}" fullword ascii
    $s7  = "AvBvYgdCYgVMufsRu, BcwQHhyvkScLLfEiBfSHRL);else bctJFuoeKUOYFR += wDKHBKjlKiXHN(YeWZQAvBvYgdCYgVMufsRu, BcwQHhyvkScLLfEiBfSHRL, " ascii
    $s8  = "IyQNflCmXNU);} while (jafai < YscYkaNzLuqWv.length);return bctJFuoeKUOYFR;}" fullword ascii
    $s9  = "function UTbtctlikeTmc(YscYkaNzLuqWv) {var enWYBiqBEHdww = BfrooXjVlZkZAEJZjvnDNay.join(KGbywraPyfBVodMRQcFtTaOV[0]);var YeWZQAv" ascii
    $s10 = "function BQpqFXYMDCdbdjTBuZ(OHciXScgIxuIK,ugmNRU){return String.fromCharCode(OHciXScgIxuIK,ugmNRU);}" fullword ascii
    $s11 = "function wDKHBKjlKiXHN(VJKWpsopTlSErFEIWepvP,GytNVoyYwsJleEJgy,LbBcpaLTtFoBZoTfmSrrRo){return String.fromCharCode(VJKWpsopTlSErF" ascii
    $s12 = "function wcZVBqZGHCaVuSqCVvssUfcn(kPUVrRhpwpoz,gmsADVAbMkbCGDroEHEd){return kPUVrRhpwpoz.indexOf(gmsADVAbMkbCGDroEHEd);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}