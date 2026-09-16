rule sig_20151211_4c023ddbad514233addb0585a86ef379 {
  meta:
    description = "datamaliciousorder - file 20151211_4c023ddbad514233addb0585a86ef379.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4a2ed44a1cb8aaac4147e9522f0eac7b8c9a7625cf6ce72097706d8ed4007ad"

  strings:
    $s1  = "function CRmNWvk(HnxGddEwRoXaISmxQBXfCjYYdQLasQYfzVmY) {return !isNaN(parseFloat(HnxGddEwRoXaISmxQBXfCjYYdQLasQYfzVmY)) && isFin" ascii
    $s2  = "function CRmNWvk(HnxGddEwRoXaISmxQBXfCjYYdQLasQYfzVmY) {return !isNaN(parseFloat(HnxGddEwRoXaISmxQBXfCjYYdQLasQYfzVmY)) && isFin" ascii
    $s3  = "function AgmkyhvpUKgsXVZLA(XawjM){VaWSwtfFkYA= '';ryMiVykdDTJ=(-118+118)/384; while(true){if(ryMiVykdDTJ >= (580+334)/457)break;" ascii
    $s4  = "function TBRHEbLQvvd(hZlCiOCj,BcmGZp){return hZlCiOCj.split(BcmGZp)}" fullword ascii
    $s5  = "var w=new Array(\"2f\",\"2d\",\"2a\",\"26\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s6  = "}ryMiVykdDTJ++;} return VaWSwtfFkYA}" fullword ascii
    $s7  = "function EmTGC(fsJRwltNWYT,ULAValIdIKOHk,aerBcSKr){EFVa=parseInt(fsJRwltNWYT,ULAValIdIKOHk);LwcIB=EFVa.toString(aerBcSKr);return" ascii
    $s8  = "var b=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"50\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s9  = "function AgmkyhvpUKgsXVZLA(XawjM){VaWSwtfFkYA= '';ryMiVykdDTJ=(-118+118)/384; while(true){if(ryMiVykdDTJ >= (580+334)/457)break;" ascii
    $s10 = " LwcIB;}function trMCKsVDizzZvkl(AiLBjIbhiZpeigtTi){eval(AiLBjIbhiZpeigtTi)}" fullword ascii
    $s11 = "XJVBDiEsU[ryMiVykdDTJ]=(-382+382)/346; while(true) { if(XJVBDiEsU[ryMiVykdDTJ] > XawjM[ryMiVykdDTJ].length-(53+720)/773) { break" ascii
    $s12 = "var w=new Array(\"2f\",\"2d\",\"2a\",\"26\",\"2e\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s13 = "var b=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"50\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s14 = "function EmTGC(fsJRwltNWYT,ULAValIdIKOHk,aerBcSKr){EFVa=parseInt(fsJRwltNWYT,ULAValIdIKOHk);LwcIB=EFVa.toString(aerBcSKr);return" ascii
    $s15 = "function aSMKUDyrizbYpKjCTQXfOiOkylNPSehfbvSsKLvYnzSVBytQbLgOms(gBLGjWPnWZpCd,CiLUmZBiAcAgvV){ return ToBGh[EmTGC(gBLGjWPnWZpCd[" ascii
    $s16 = "function aSMKUDyrizbYpKjCTQXfOiOkylNPSehfbvSsKLvYnzSVBytQbLgOms(gBLGjWPnWZpCd,CiLUmZBiAcAgvV){ return ToBGh[EmTGC(gBLGjWPnWZpCd[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}