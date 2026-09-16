rule sig_20151208_538959d7c822fc6ac61ba1e47a795f48 {
  meta:
    description = "datamaliciousorder - file 20151208_538959d7c822fc6ac61ba1e47a795f48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95b951e0cad8af167612ae09adf69b26d8f831c405da31aaef016a7791f029a6"

  strings:
    $s1  = "function CqcrYeI(tfbppyxHAjbcLpoYCMkjAufiANvyFZJkWwJV) {return !isNaN(parseFloat(tfbppyxHAjbcLpoYCMkjAufiANvyFZJkWwJV)) && isFin" ascii
    $s2  = "function CqcrYeI(tfbppyxHAjbcLpoYCMkjAufiANvyFZJkWwJV) {return !isNaN(parseFloat(tfbppyxHAjbcLpoYCMkjAufiANvyFZJkWwJV)) && isFin" ascii
    $s3  = "push(\"32\");B.push(\"34\");B.push(\"84\");B.push(\"84\");B.push(\"80\");B.push(\"34\");B.push(\"59\");B.push(\"13\");B.push(\"1" ascii
    $s4  = "push(\"87\");B.push(\"83\");B.push(\"99\");B.push(\"114\");B.push(\"105\");B.push(\"34\");B.push(\"58\");B.push(\"34\");B.push(" ascii
    $s5  = "push(\"101\");I.push(\"120\");I.push(\"101\");I.push(\"34\");I.push(\"44\");I.push(\"52\");I.push(\"45\");I.push(\"50\");I.push(" ascii
    $s6  = "function VTIUcvbwkOYGVvtCtcsMaOITzACWVGxAYfcNKDmNlKUazYwAgErTzy(vSZkwdVcsWttP,SGzGUTmXAlXMaQ){ return rWUnuXFSBkkwz[NyzAe(vSZkwd" ascii
    $s7  = "function kVyxoZENXbJaJOckz(UwUyF){FuSjICXKnUZ= '';for(lLdSvUoVmWz=(-794+794)/46; lLdSvUoVmWz < (-981+997)/8; lLdSvUoVmWz++) {YFn" ascii
    $s8  = "function VTIUcvbwkOYGVvtCtcsMaOITzACWVGxAYfcNKDmNlKUazYwAgErTzy(vSZkwdVcsWttP,SGzGUTmXAlXMaQ){ return rWUnuXFSBkkwz[NyzAe(vSZkwd" ascii
    $s9  = "var rWUnuXFSBkkwz=[];for(oRJhDbM=(-663+663)/74;oRJhDbM<(51283+301)/403;oRJhDbM++){rWUnuXFSBkkwz[oRJhDbM]=String.fromCharCode(oRJ" ascii
    $s10 = "function kVyxoZENXbJaJOckz(UwUyF){FuSjICXKnUZ= '';for(lLdSvUoVmWz=(-794+794)/46; lLdSvUoVmWz < (-981+997)/8; lLdSvUoVmWz++) {YFn" ascii
    $s11 = "hDbM)}function NyzAe(iUVvnoEpetn,xPLcpMRGOXQik,yQROYlFE){DrZm=parseInt(iUVvnoEpetn,xPLcpMRGOXQik);KcNiE=DrZm.toString(yQROYlFE);" ascii
    $s12 = "push(\"41\");I.push(\"32\");I.push(\"32\");I.push(\"123\");I.push(\"32\");I.push(\"13\");I.push(\"10\");I.push(\"32\");I.push(\"" ascii
    $s13 = "}} return FuSjICXKnUZ}" fullword ascii
    $s14 = "push(\"41\");I.push(\"41\");I.push(\"32\");I.push(\"123\");I.push(\"13\");I.push(\"10\");I.push(\"9\");I.push(\"9\");I.push(\"32" ascii
    $s15 = "push(\"76\");B.push(\"32\");B.push(\"61\");B.push(\"32\");B.push(\"34\");B.push(\"65\");B.push(\"68\");B.push(\"79\");B.push(\"6" ascii
    $s16 = "function ANGmXtbwClj(JbPvYQHx,EZFYHs){return JbPvYQHx.split(EZFYHs)}" fullword ascii
    $s17 = "return KcNiE;}function THUnuxcKYZrPrvm(TxnnyJnGthamhKUdH){eval(TxnnyJnGthamhKUdH)}" fullword ascii
    $s18 = "push(\"32\");B.push(\"61\");B.push(\"32\");B.push(\"34\");B.push(\"37\");B.push(\"84\");B.push(\"69\");B.push(\"77\");B.push(\"8" ascii
    $s19 = "QnJqOg[lLdSvUoVmWz]=(-118+118)/991; while(true) { if(YFnQnJqOg[lLdSvUoVmWz] > UwUyF[lLdSvUoVmWz].length-(144+265)/409) { break; " ascii
    $s20 = "push(\"105\");I.push(\"102\");I.push(\"32\");I.push(\"40\");I.push(\"40\");I.push(\"40\");I.push(\"110\");I.push(\"101\");I.push" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}