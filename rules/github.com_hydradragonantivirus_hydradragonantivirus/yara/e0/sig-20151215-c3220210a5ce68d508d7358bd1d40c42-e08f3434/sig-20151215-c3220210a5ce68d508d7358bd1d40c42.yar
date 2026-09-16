rule sig_20151215_c3220210a5ce68d508d7358bd1d40c42 {
  meta:
    description = "datamaliciousorder - file 20151215_c3220210a5ce68d508d7358bd1d40c42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b9abbc7bff73b252fb8587822346c307df7261d53e901109ed45cb98965a725"

  strings:
    $s1  = "ath.pow(Math.cos(40), 2) - 1)); while(true) { if(GdyKVVTeC[NJzXYjjmyJD] > UbBNa[NJzXYjjmyJD].length-(-229+922)/693) { break; } i" ascii
    $s2  = "pow(Math.cos(670), 2) - 1)));} GdyKVVTeC[NJzXYjjmyJD]++;}} return yfoEgOpVhTY}" fullword ascii
    $s3  = "function jAYQnRKWiHhmJMUVN(UbBNa){yfoEgOpVhTY= O[1760];for(NJzXYjjmyJD=Math.round((Math.pow(Math.sin(878), 2) + Math.pow(Math.co" ascii
    $s4  = "function jAYQnRKWiHhmJMUVN(UbBNa){yfoEgOpVhTY= O[1760];for(NJzXYjjmyJD=Math.round((Math.pow(Math.sin(878), 2) + Math.pow(Math.co" ascii
    $s5  = "RGYCeuOneRqfsjKJUfJkVYLgMyCITWaTejS([UbBNa[NJzXYjjmyJD][GdyKVVTeC[NJzXYjjmyJD]]], Math.round((Math.pow(Math.sin(670), 2) + Math." ascii
    $s6  = "function v(FDarPSZGOzGr,FeBpcBnmyidSJw){FDarPSZGOzGr.push(FeBpcBnmyidSJw);}function B0(awTvnaxrDeJfEGil){if(ewyvoqP(awTvnaxrDeJf" ascii
    $s7  = "EGil)) {return (String.fromCharCode(awTvnaxrDeJfEGil) + String.fromCharCode((62776+648)/991));}}" fullword ascii
    $s8  = "function ewyvoqP(jgPOsXEjHUMWjlGWbicRGAobBKYBBHtZPVDj) {return !isNaN(parseFloat(jgPOsXEjHUMWjlGWbicRGAobBKYBBHtZPVDj)) && isFin" ascii
    $s9  = "function ewyvoqP(jgPOsXEjHUMWjlGWbicRGAobBKYBBHtZPVDj) {return !isNaN(parseFloat(jgPOsXEjHUMWjlGWbicRGAobBKYBBHtZPVDj)) && isFin" ascii
    $s10 = "function sPKprOIHEkutTCEYCmVRGYCeuOneRqfsjKJUfJkVYLgMyCITWaTejS(NzjizffkImGso,QMMiIhtFiipwTI){ return iyKysxg[ITzvsbxP[ckbnA(Nzj" ascii
    $s11 = "function v(FDarPSZGOzGr,FeBpcBnmyidSJw){FDarPSZGOzGr.push(FeBpcBnmyidSJw);}function B0(awTvnaxrDeJfEGil){if(ewyvoqP(awTvnaxrDeJf" ascii
    $s12 = "function qpSNelpExKFJgsu(bhubOdHSyklndtOTK){eval(bhubOdHSyklndtOTK)}" fullword ascii
    $s13 = "function ckbnA(ZXRorIqfusx,HjFmVehWXUtKF,EdfLWQtU){LAaU=parseInt(ZXRorIqfusx,HjFmVehWXUtKF);vPZLM=LAaU.toString(EdfLWQtU);return" ascii
    $s14 = "var O=new Array();" fullword ascii
    $s15 = "function cikvEGPJkNz(jzmIdgfA,XTXgKu){return jzmIdgfA.split(XTXgKu)}" fullword ascii
    $s16 = "function sPKprOIHEkutTCEYCmVRGYCeuOneRqfsjKJUfJkVYLgMyCITWaTejS(NzjizffkImGso,QMMiIhtFiipwTI){ return iyKysxg[ITzvsbxP[ckbnA(Nzj" ascii
    $s17 = " vPZLM;}function qpSNelpExKFJgsu(bhubOdHSyklndtOTK,OhTdsEcaafoXbDsIuFQSNBoTOQVvYaPOfo,pGslRDNbZVTxGCMkAhQtMYoNbWiJiXhPJNm){eval(" ascii
    $s18 = "function ckbnA(ZXRorIqfusx,HjFmVehWXUtKF,EdfLWQtU){LAaU=parseInt(ZXRorIqfusx,HjFmVehWXUtKF);vPZLM=LAaU.toString(EdfLWQtU);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}