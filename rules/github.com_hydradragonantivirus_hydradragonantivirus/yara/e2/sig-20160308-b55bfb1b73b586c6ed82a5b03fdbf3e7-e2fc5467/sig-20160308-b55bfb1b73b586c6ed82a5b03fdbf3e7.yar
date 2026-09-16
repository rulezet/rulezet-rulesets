rule sig_20160308_b55bfb1b73b586c6ed82a5b03fdbf3e7 {
  meta:
    description = "datamaliciousorder - file 20160308_b55bfb1b73b586c6ed82a5b03fdbf3e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b66d243b19b8a4e6804ba7a7f6cf5e332edbe8fea2f9551b0d36a2dfa6a78203"

  strings:
    $s1  = "function UTxlOGLA(Mup) {" fullword ascii
    $s2  = "return tgHmjqd[0] + tgHmjqd[2] + tgHmjqd[4] + \".F\" + tgHmjqd[7] + tgHmjqd[9] + tgHmjqd[12] + tgHmjqd[14];" fullword ascii
    $s3  = "var ex = true  , OlTQ = hAk[7] + hAk[9] + hAk[11];" fullword ascii
    $s4  = "GBAtP.open(AFWGu,tTWeg,false);" fullword ascii
    $s5  = "var hAk = (\"2.XMLHTTP cVzMPjK Eheeh XML ream St JPfrtSqr AD DmUnIWf O LVtd D\").split(\" \");" fullword ascii
    $s6  = "var tgHmjqd = \"Sc hNFGOIq r AQIfTXLnr ipting ZSacGRS AKJ ile RgdZVZcWQEAYEo System EQ dTlfP Obj kkcqln ect MtBLcoy\".split(\" " ascii
    $s7  = "function naKC(Gbfgk) {" fullword ascii
    $s8  = "function eEKSjvcdY(Evpcw,tOJaD,ZKpUJ,Lgpr) {" fullword ascii
    $s9  = "return fQMM.responseBody;" fullword ascii
    $s10 = "function jhlU(dFzXN) {" fullword ascii
    $s11 = "return asPss.status;" fullword ascii
    $s12 = "yOV = D; break; " fullword ascii
    $s13 = "function maCV(YppHz,XWnas) {" fullword ascii
    $s14 = "if(D>=x.length) {break;}" fullword ascii
    $s15 = "if (dFzXN == 955-755){return true;} else {return false;}" fullword ascii
    $s16 = "if (((new Date())>0,7517712888)) {" fullword ascii
    $s17 = "function NZrX(asPss) {" fullword ascii
    $s18 = "function rjiAIRn(fQMM) {" fullword ascii
    $s19 = "return NXVuhdY" fullword ascii
    $s20 = "if (EFOOp > 180823-845){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}