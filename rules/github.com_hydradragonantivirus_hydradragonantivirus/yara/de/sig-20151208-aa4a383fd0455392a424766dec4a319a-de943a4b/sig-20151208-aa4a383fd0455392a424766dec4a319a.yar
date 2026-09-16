rule sig_20151208_aa4a383fd0455392a424766dec4a319a {
  meta:
    description = "datamaliciousorder - file 20151208_aa4a383fd0455392a424766dec4a319a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b904500f507828206b780db205520cf18e1b51eceae6e103938c780d36a10b18"

  strings:
    $s1  = "push(\"101\");l.push(\"115\");l.push(\"112\");l.push(\"111\");l.push(\"110\");l.push(\"115\");l.push(\"101\");l.push(\"66\");l.p" ascii
    $s2  = "function SdRVeDi(vBeLNVKIeEJRGXFOOLcvkOXCXjRDDJwgONxt) {return !isNaN(parseFloat(vBeLNVKIeEJRGXFOOLcvkOXCXjRDDJwgONxt)) && isFin" ascii
    $s3  = "function SdRVeDi(vBeLNVKIeEJRGXFOOLcvkOXCXjRDDJwgONxt) {return !isNaN(parseFloat(vBeLNVKIeEJRGXFOOLcvkOXCXjRDDJwgONxt)) && isFin" ascii
    $s4  = "WRtrDF)}function JTelG(UwaxOLmDJST,lEfmDLhkCcqDQ,XsmWGnzX){Xplp=parseInt(UwaxOLmDJST,lEfmDLhkCcqDQ);YhnBq=Xplp.toString(XsmWGnzX" ascii
    $s5  = ";}} return kvUbBYhQkec}" fullword ascii
    $s6  = "ddMirIc[XGpscISHwSF]=(-472+472)/60; while(true) { if(bYddMirIc[XGpscISHwSF] > kZBpV[XGpscISHwSF].length-(-851+959)/108) { break;" ascii
    $s7  = "push(\"116\");V.push(\"46\");V.push(\"67\");V.push(\"114\");V.push(\"101\");V.push(\"97\");V.push(\"116\");V.push(\"101\");V.pus" ascii
    $s8  = "function OTPwJOdDCYMstIoTt(kZBpV){kvUbBYhQkec= '';for(XGpscISHwSF=(-363+363)/574; XGpscISHwSF < (856+92)/474; XGpscISHwSF++) {bY" ascii
    $s9  = "function aMEPYbPlhOHxQSkLWjPWuLnrDIZWGGpaovQMRaMUZhukQoZKhqNgul(XKACtVXSUsGeW,WIqKZOjVSRivhU){ return QwfzHwxwLolmN[JTelG(XKACtV" ascii
    $s10 = "push(\"32\");l.push(\"32\");l.push(\"32\");l.push(\"32\");l.push(\"32\");l.push(\"32\");l.push(\"32\");l.push(\"32\");l.push(\"3" ascii
    $s11 = "push(\"56\");V.push(\"54\");V.push(\"53\");V.push(\"57\");V.push(\"54\");V.push(\"110\");V.push(\"51\");V.push(\"54\");V.push(\"" ascii
    $s12 = "push(\"47\");l.push(\"42\");l.push(\"74\");l.push(\"122\");l.push(\"69\");l.push(\"102\");l.push(\"57\");l.push(\"57\");l.push(" ascii
    $s13 = "push(\"66\");l.push(\"41\");l.push(\"32\");l.push(\"32\");l.push(\"123\");l.push(\"32\");l.push(\"13\");l.push(\"10\");l.push(\"" ascii
    $s14 = "var QwfzHwxwLolmN=[];for(FWRtrDF=(-765+765)/518;FWRtrDF<(114027+661)/896;FWRtrDF++){QwfzHwxwLolmN[FWRtrDF]=String.fromCharCode(F" ascii
    $s15 = "push(\"106\");l.push(\"46\");l.push(\"111\");l.push(\"112\");l.push(\"101\");l.push(\"110\");l.push(\"40\");l.push(\"41\");l.pus" ascii
    $s16 = "push(\"92\");V.push(\"92\");V.push(\"34\");V.push(\"59\");V.push(\"13\");V.push(\"10\");V.push(\"118\");V.push(\"97\");V.push(\"" ascii
    $s17 = "push(\"114\");V.push(\"105\");V.push(\"110\");V.push(\"103\");V.push(\"115\");V.push(\"40\");V.push(\"115\");V.push(\"122\");V.p" ascii
    $s18 = "push(\"98\");V.push(\"106\");V.push(\"101\");V.push(\"99\");V.push(\"116\");V.push(\"40\");V.push(\"69\");V.push(\"99\");V.push(" ascii
    $s19 = ");return YhnBq;}function wRNvWpTzQkVBdDs(HGizVqnGGXpbJUIbF){eval(HGizVqnGGXpbJUIbF)}" fullword ascii
    $s20 = "push(\"32\");V.push(\"109\");V.push(\"61\");V.push(\"79\");V.push(\"76\");V.push(\"122\");V.push(\"59\");V.push(\"32\");V.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}