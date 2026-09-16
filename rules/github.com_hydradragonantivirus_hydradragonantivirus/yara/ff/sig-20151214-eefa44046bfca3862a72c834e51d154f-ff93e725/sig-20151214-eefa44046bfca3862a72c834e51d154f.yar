rule sig_20151214_eefa44046bfca3862a72c834e51d154f {
  meta:
    description = "datamaliciousorder - file 20151214_eefa44046bfca3862a72c834e51d154f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "352d02914e940da3b43ee7a6506f1633143a67b188153a3e01571bbcddf97470"

  strings:
    $s1  = "ath.pow(Math.cos(660), 2) - 1)); while(true) { if(dQGkCCCCC[tpIzOxuKiCp] > CVqbv[tpIzOxuKiCp].length-(-340+654)/314) { break; } " ascii
    $s2  = ".pow(Math.cos(456), 2) - 1)));} dQGkCCCCC[tpIzOxuKiCp]++;}} return eCiWQtNKQsj}" fullword ascii
    $s3  = "function oJZkzjJLnncTpkWwE(CVqbv){eCiWQtNKQsj= a[1787];for(tpIzOxuKiCp=Math.round((Math.pow(Math.sin(804), 2) + Math.pow(Math.co" ascii
    $s4  = "ZJABTrglAIHUgxVLmDbsOMvBcdgrKGoHMcgb([CVqbv[tpIzOxuKiCp][dQGkCCCCC[tpIzOxuKiCp]]], Math.round((Math.pow(Math.sin(456), 2) + Math" ascii
    $s5  = "function oJZkzjJLnncTpkWwE(CVqbv){eCiWQtNKQsj= a[1787];for(tpIzOxuKiCp=Math.round((Math.pow(Math.sin(804), 2) + Math.pow(Math.co" ascii
    $s6  = "function I(tSfWTMiDdznp,mKqxPEZMeNnjyC){tSfWTMiDdznp.push(mKqxPEZMeNnjyC);}function v1(gDIWTQzAAZORVGxk){if(YaPoBBp(gDIWTQzAAZOR" ascii
    $s7  = "VGxk)) {return (String.fromCharCode(gDIWTQzAAZORVGxk) + String.fromCharCode((61855+554)/879));}}" fullword ascii
    $s8  = "function YaPoBBp(qjiXRDRkOGQhRtYrdyuWqkpTlQtdWabRXhiQ) {return !isNaN(parseFloat(qjiXRDRkOGQhRtYrdyuWqkpTlQtdWabRXhiQ)) && isFin" ascii
    $s9  = "function YaPoBBp(qjiXRDRkOGQhRtYrdyuWqkpTlQtdWabRXhiQ) {return !isNaN(parseFloat(qjiXRDRkOGQhRtYrdyuWqkpTlQtdWabRXhiQ)) && isFin" ascii
    $s10 = "var a=new Array();" fullword ascii
    $s11 = "function imHydhOAJBiYyTZOTdZJABTrglAIHUgxVLmDbsOMvBcdgrKGoHMcgb(BqwylfyJptjjT,yxkuLHsGxIBGOL){ return YiGRGif[wGFNMaJl[xqpeU(Bqw" ascii
    $s12 = "function xqpeU(rOjLjmKelrW,jSflFyBLLWJHM,ceBrBnhG){UIvE=parseInt(rOjLjmKelrW,jSflFyBLLWJHM);VpkZo=UIvE.toString(ceBrBnhG);return" ascii
    $s13 = " VpkZo;}function rBUrARwhUkhdLUq(SFVRxjheuJnFqirEh,DJpkyzjPzLqKRfEVoPGRUVRkWmMrDSNfoT,BRWloqWZoMxaFNIZyWuvCEZXFnqMNdpqkWd){eval(" ascii
    $s14 = "function imHydhOAJBiYyTZOTdZJABTrglAIHUgxVLmDbsOMvBcdgrKGoHMcgb(BqwylfyJptjjT,yxkuLHsGxIBGOL){ return YiGRGif[wGFNMaJl[xqpeU(Bqw" ascii
    $s15 = "function rBUrARwhUkhdLUq(SFVRxjheuJnFqirEh){eval(SFVRxjheuJnFqirEh)}" fullword ascii
    $s16 = "function AVbTvwVOIAu(BWLEfVLZ,VSUOwD){return BWLEfVLZ.split(VSUOwD)}" fullword ascii
    $s17 = "function I(tSfWTMiDdznp,mKqxPEZMeNnjyC){tSfWTMiDdznp.push(mKqxPEZMeNnjyC);}function v1(gDIWTQzAAZORVGxk){if(YaPoBBp(gDIWTQzAAZOR" ascii
    $s18 = "function xqpeU(rOjLjmKelrW,jSflFyBLLWJHM,ceBrBnhG){UIvE=parseInt(rOjLjmKelrW,jSflFyBLLWJHM);VpkZo=UIvE.toString(ceBrBnhG);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}