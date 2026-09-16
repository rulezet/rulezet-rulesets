rule sig_20151217_2bd8b9b8fca3acca946859ca175c9a06 {
  meta:
    description = "datamaliciousorder - file 20151217_2bd8b9b8fca3acca946859ca175c9a06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "871d63507199d28aa626bd5b5dfeb70efa3603c1acf9ae195f8de919c95ecbde"

  strings:
    $s1  = "Math.cos(517), 2) - 1)));} VoiktzUpJ[qoxtUSUZnuP]++;}qoxtUSUZnuP++;} return HpdRRmQxuQn}" fullword ascii
    $s2  = ") - 1));while(true){if (qoxtUSUZnuP >= (412+74)/81){break;}VoiktzUpJ[qoxtUSUZnuP]=Math.round((Math.pow(Math.sin(874), 2) + Math." ascii
    $s3  = "pow(Math.cos(874), 2) - 1)); while(true) { if(VoiktzUpJ[qoxtUSUZnuP] > lYJgN[qoxtUSUZnuP].length-(-418+607)/189) { break; } if (" ascii
    $s4  = "function ZUeQXAcXFgnfKHPsX(lYJgN){HpdRRmQxuQn= '';qoxtUSUZnuP=Math.round((Math.pow(Math.sin(731), 2) + Math.pow(Math.cos(731), 2" ascii
    $s5  = "function ZUeQXAcXFgnfKHPsX(lYJgN){HpdRRmQxuQn= '';qoxtUSUZnuP=Math.round((Math.pow(Math.sin(731), 2) + Math.pow(Math.cos(731), 2" ascii
    $s6  = "function PPPDaSzYZXyYORr(fzTMpsRfSaSYAeXLwVJ) {return parseFloat(fzTMpsRfSaSYAeXLwVJ);}" fullword ascii
    $s7  = "function ytFJLjY(fMpGQHfvWSlboXzgrOpLojFxktqZxPBWMLKn) {return !JKryvPsooHv(PPPDaSzYZXyYORr(fMpGQHfvWSlboXzgrOpLojFxktqZxPBWMLKn" ascii
    $s8  = "var S = new Array();S[0]=[];S[0][0]='d';S[0][1]='a';S[0][2]='d';S[0][3]='a';S[0][4]='46';S[0][5]='3d';S[0][6]='42';S[0][7]='14';" ascii
    $s9  = "function B(KyypSmqbsVVP,ZJYUPePgrEKIHA){KyypSmqbsVVP.push(ZJYUPePgrEKIHA);}" fullword ascii
    $s10 = "function ytFJLjY(fMpGQHfvWSlboXzgrOpLojFxktqZxPBWMLKn) {return !JKryvPsooHv(PPPDaSzYZXyYORr(fMpGQHfvWSlboXzgrOpLojFxktqZxPBWMLKn" ascii
    $s11 = "function TxwQs(tdKpLUHkLFD,EYICmvNdObuYG,EYIJlERt){SIWS=YmrUzzvuNOQgUuwjb(tdKpLUHkLFD,EYICmvNdObuYG);kKMXt=SIWS.toString(EYIJlER" ascii
    $s12 = "t);return kKMXt;}" fullword ascii
    $s13 = "function JKryvPsooHv(ZiKHCoRlVkfPDh) {return isNaN(ZiKHCoRlVkfPDh);}" fullword ascii
    $s14 = "function YmrUzzvuNOQgUuwjb(vDreEQSLCW,CIvZbVUdYY) {return parseInt(vDreEQSLCW,CIvZbVUdYY);}" fullword ascii
    $s15 = "function nXASlpArkkTudoUVwenCkPBhpHQtESIWcdlIuXcUueUHmWBFQeJYTi(ZcKnNiaKiphiv,XRQnWNIYkdeKWU){ return nmiOKlx[fZInbXjY[TxwQs(ZcK" ascii
    $s16 = "function nXASlpArkkTudoUVwenCkPBhpHQtESIWcdlIuXcUueUHmWBFQeJYTi(ZcKnNiaKiphiv,XRQnWNIYkdeKWU){ return nmiOKlx[fZInbXjY[TxwQs(ZcK" ascii
    $s17 = "var S = new Array();S[0]=[];S[0][0]='d';S[0][1]='a';S[0][2]='d';S[0][3]='a';S[0][4]='46';S[0][5]='3d';S[0][6]='42';S[0][7]='14';" ascii
    $s18 = "function TxwQs(tdKpLUHkLFD,EYICmvNdObuYG,EYIJlERt){SIWS=YmrUzzvuNOQgUuwjb(tdKpLUHkLFD,EYICmvNdObuYG);kKMXt=SIWS.toString(EYIJlER" ascii
    $s19 = "function e(vMNklDTaIJkUrK,WLgeBWrCLHGta,bQqPrkmxGBz) {vMNklDTaIJkUrK[WLgeBWrCLHGta]=bQqPrkmxGBz;}" fullword ascii
    $s20 = "function bGgHNtXFAlhb(HsdUydSHoJpyq) {return isFinite(HsdUydSHoJpyq);}" fullword ascii

  condition:
    uint16(0) == 0x5a66 and
    8 of them
}