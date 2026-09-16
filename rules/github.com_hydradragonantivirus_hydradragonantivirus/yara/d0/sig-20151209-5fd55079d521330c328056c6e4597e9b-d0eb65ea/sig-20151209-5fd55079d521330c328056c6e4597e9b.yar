rule sig_20151209_5fd55079d521330c328056c6e4597e9b {
  meta:
    description = "datamaliciousorder - file 20151209_5fd55079d521330c328056c6e4597e9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb6d47da4ce00b65211f9c0586de23ace906501345d5650fa18a5f6f75ded7a9"

  strings:
    $s1  = "function BEvapcoMAhFJULBhddkGQuEGzsatPHvSKNmdaxMaKQlhBCdtSBukwJ(UnNhUAdxVBQZl,tFOCyjDXdxYbGq){ return yAWKE[eWKvi(UnNhUAdxVBQZl[" ascii
    $s2  = "function bLUjzVgfqlYqJUgcZ(eMuZg){vDeVwcJPkXl= '';for(aTqcMyEhTtC=(-669+669)/121; aTqcMyEhTtC < (465+269)/367; aTqcMyEhTtC++) {t" ascii
    $s3  = "function bPzGmsN(CgdjiTpqqsUWHbedLOyVJpVCeGcgeWvqRGXa) {return !isNaN(parseFloat(CgdjiTpqqsUWHbedLOyVJpVCeGcgeWvqRGXa)) && isFin" ascii
    $s4  = "function BEvapcoMAhFJULBhddkGQuEGzsatPHvSKNmdaxMaKQlhBCdtSBukwJ(UnNhUAdxVBQZl,tFOCyjDXdxYbGq){ return yAWKE[eWKvi(UnNhUAdxVBQZl[" ascii
    $s5  = "function bPzGmsN(CgdjiTpqqsUWHbedLOyVJpVCeGcgeWvqRGXa) {return !isNaN(parseFloat(CgdjiTpqqsUWHbedLOyVJpVCeGcgeWvqRGXa)) && isFin" ascii
    $s6  = "XBlSIEfG[aTqcMyEhTtC]=(-85+85)/283; while(true) { if(tXBlSIEfG[aTqcMyEhTtC] > eMuZg[aTqcMyEhTtC].length-(-838+864)/26) { break; " ascii
    $s7  = " kvzEc;}function hdVAfZxRxgTFzgJ(jSNHuReldBsgDcepk){eval(jSNHuReldBsgDcepk)}" fullword ascii
    $s8  = "function eWKvi(cvFKzIzyicu,FMFaeExNetwDp,CpCWesGb){ATUM=parseInt(cvFKzIzyicu,FMFaeExNetwDp);kvzEc=ATUM.toString(CpCWesGb);return" ascii
    $s9  = "function WfoIqJDYuOj(CroglSqE,vpLtyz){return CroglSqE.split(vpLtyz)}" fullword ascii
    $s10 = " return vDeVwcJPkXl}" fullword ascii
    $s11 = "function bLUjzVgfqlYqJUgcZ(eMuZg){vDeVwcJPkXl= '';for(aTqcMyEhTtC=(-669+669)/121; aTqcMyEhTtC < (465+269)/367; aTqcMyEhTtC++) {t" ascii
    $s12 = "function eWKvi(cvFKzIzyicu,FMFaeExNetwDp,CpCWesGb){ATUM=parseInt(cvFKzIzyicu,FMFaeExNetwDp);kvzEc=ATUM.toString(CpCWesGb);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}