rule sig_20151208_de3f5e8e03ddce568902ad2d8c5ddbe9 {
  meta:
    description = "datamaliciousorder - file 20151208_de3f5e8e03ddce568902ad2d8c5ddbe9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0412a4685c2b69eb1999130ef148b4e6812aa9f3dba07de497e2660cfb666f3"

  strings:
    $s1  = "function CvSBklu(dUsMXWkKxnPhKSBcKMDAWNJQlOJlNNSXeTrj) {return !isNaN(parseFloat(dUsMXWkKxnPhKSBcKMDAWNJQlOJlNNSXeTrj)) && isFin" ascii
    $s2  = "function CvSBklu(dUsMXWkKxnPhKSBcKMDAWNJQlOJlNNSXeTrj) {return !isNaN(parseFloat(dUsMXWkKxnPhKSBcKMDAWNJQlOJlNNSXeTrj)) && isFin" ascii
    $s3  = "push(\"115\");s.push(\"112\");s.push(\"111\");s.push(\"110\");s.push(\"115\");s.push(\"101\");s.push(\"66\");s.push(\"111\");s.p" ascii
    $s4  = "push(\"45\");T.push(\"105\");T.push(\"110\");T.push(\"99\");T.push(\"108\");T.push(\"117\");T.push(\"100\");T.push(\"101\");T.pu" ascii
    $s5  = "function AwRUQXgZdYewyfjsL(yuWIy){BJgJYCcnDpy= '';for(WbcrWHNJlUX=(-133+133)/1; WbcrWHNJlUX < (1174+444)/809; WbcrWHNJlUX++) {NL" ascii
    $s6  = "push(\"34\");T.push(\"34\");T.push(\"41\");T.push(\"43\");T.push(\"34\");T.push(\"112\");T.push(\"116\");T.push(\"46\");T.push(" ascii
    $s7  = "push(\"9\");s.push(\"9\");s.push(\"125\");s.push(\"59\");s.push(\"32\");s.push(\"13\");s.push(\"10\");s.push(\"32\");s.push(\"32" ascii
    $s8  = "NrUTG)}function TRbfH(RnyFtbnscoR,dWlUzxYAmCDrq,jVSHyhVl){kfgB=parseInt(RnyFtbnscoR,dWlUzxYAmCDrq);uPvuf=kfgB.toString(jVSHyhVl)" ascii
    $s9  = "function oZoKVfOEBCbxruazhlJtnbYbWKFGMLHLFDNOOzbjFzuRQgZSDRgeOD(SPERYSHJTIwby,glflOEANqFOpXF){ return UdpJBNrcsNApR[TRbfH(SPERYS" ascii
    $s10 = "function asPGOqPoyQe(UfzlDOUG,WYuyuu){return UfzlDOUG.split(WYuyuu)}" fullword ascii
    $s11 = "function oZoKVfOEBCbxruazhlJtnbYbWKFGMLHLFDNOOzbjFzuRQgZSDRgeOD(SPERYSHJTIwby,glflOEANqFOpXF){ return UdpJBNrcsNApR[TRbfH(SPERYS" ascii
    $s12 = "function AwRUQXgZdYewyfjsL(yuWIy){BJgJYCcnDpy= '';for(WbcrWHNJlUX=(-133+133)/1; WbcrWHNJlUX < (1174+444)/809; WbcrWHNJlUX++) {NL" ascii
    $s13 = "var UdpJBNrcsNApR=[];for(wNNrUTG=(-840+840)/419;wNNrUTG<(14733+499)/119;wNNrUTG++){UdpJBNrcsNApR[wNNrUTG]=String.fromCharCode(wN" ascii
    $s14 = "push(\"61\");s.push(\"32\");s.push(\"100\");s.push(\"59\");s.push(\"32\");s.push(\"98\");s.push(\"114\");s.push(\"101\");s.push(" ascii
    $s15 = "push(\"116\");s.push(\"46\");s.push(\"67\");s.push(\"114\");s.push(\"101\");s.push(\"97\");s.push(\"116\");s.push(\"101\");s.pus" ascii
    $s16 = ";return uPvuf;}function IMnKyzGDgNtoqZM(eOQyFMPlBvYVXxifI){eval(eOQyFMPlBvYVXxifI)}" fullword ascii
    $s17 = "push(\"110\");T.push(\"115\");T.push(\"122\");T.push(\"32\");T.push(\"61\");T.push(\"32\");T.push(\"34\");T.push(\"50\");T.push(" ascii
    $s18 = "push(\"46\");s.push(\"111\");s.push(\"112\");s.push(\"101\");s.push(\"110\");s.push(\"40\");s.push(\"112\");s.push(\"111\");s.pu" ascii
    $s19 = "fSHoSCV[WbcrWHNJlUX]=(-484+484)/81; while(true) { if(NLfSHoSCV[WbcrWHNJlUX] > yuWIy[WbcrWHNJlUX].length-(-159+260)/101) { break;" ascii
    $s20 = ";}} return BJgJYCcnDpy}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}