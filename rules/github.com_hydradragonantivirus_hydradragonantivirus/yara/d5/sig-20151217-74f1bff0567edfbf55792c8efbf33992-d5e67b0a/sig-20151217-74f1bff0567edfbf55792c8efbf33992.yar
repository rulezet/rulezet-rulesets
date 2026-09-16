rule sig_20151217_74f1bff0567edfbf55792c8efbf33992 {
  meta:
    description = "datamaliciousorder - file 20151217_74f1bff0567edfbf55792c8efbf33992.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c9d3622634cfc36952a9880b969b259da3834d8051799c1ab89e92bb1e1e1e7"

  strings:
    $s1  = ") - 1));while(true){if (EreQgSOwNcs >= (3001+431)/572){break;}NkkbDeVAn[EreQgSOwNcs]=Math.round((Math.pow(Math.sin(448), 2) + Ma" ascii
    $s2  = ".pow(Math.cos(764), 2) - 1)));} NkkbDeVAn[EreQgSOwNcs]++;}EreQgSOwNcs++;} return inwcmiVAFeP}" fullword ascii
    $s3  = "function SLVTNNQCZQSjcfqqr(JxTGK){inwcmiVAFeP= '';EreQgSOwNcs=Math.round((Math.pow(Math.sin(458), 2) + Math.pow(Math.cos(458), 2" ascii
    $s4  = "th.pow(Math.cos(448), 2) - 1)); while(true) { if(NkkbDeVAn[EreQgSOwNcs] > JxTGK[EreQgSOwNcs].length-(-554+717)/163) { break; } i" ascii
    $s5  = "sZRAdtrZXRJsbGDetMRWsDJmLNFFxIRSOBsz([JxTGK[EreQgSOwNcs][NkkbDeVAn[EreQgSOwNcs]]], Math.round((Math.pow(Math.sin(764), 2) + Math" ascii
    $s6  = "function SLVTNNQCZQSjcfqqr(JxTGK){inwcmiVAFeP= '';EreQgSOwNcs=Math.round((Math.pow(Math.sin(458), 2) + Math.pow(Math.cos(458), 2" ascii
    $s7  = "function gjNMtQm(FEtMzKHZuaTAUEYFNPrNrlRYXIdZdYDikXiF) {return !UEGbEGKmcDg(JwPaXHeURypXwJJ(FEtMzKHZuaTAUEYFNPrNrlRYXIdZdYDikXiF" ascii
    $s8  = "function A(lIqoiztdWpSE,JSeXFXCWuhGSyo){lIqoiztdWpSE.push(JSeXFXCWuhGSyo);}" fullword ascii
    $s9  = "function UmgZrQBDVrrZcoV(tUOkyOTGxqmhHJxXj,yuxxVHpUnbtLzUAbnIqWsioSPBxGmMNCOr,aiaYIOQaUErfReJRkqykrmJqIqexAJpFqPz){eval(tUOkyOTG" ascii
    $s10 = "function gjNMtQm(FEtMzKHZuaTAUEYFNPrNrlRYXIdZdYDikXiF) {return !UEGbEGKmcDg(JwPaXHeURypXwJJ(FEtMzKHZuaTAUEYFNPrNrlRYXIdZdYDikXiF" ascii
    $s11 = "var r = new Array();r[0]=[];r[0][0]='d';r[0][1]='a';r[0][2]='d';r[0][3]='a';r[0][4]='46';r[0][5]='3d';r[0][6]='42';r[0][7]='14';" ascii
    $s12 = "function VtXrRcDkIoHJqQyFkSsZRAdtrZXRJsbGDetMRWsDJmLNFFxIRSOBsz(smOXvTSbBqZmb,tEMoIcBZBZCBtu){ return GwtyojR[jYNFThYu[pASqK(smO" ascii
    $s13 = "function e(wotCTLNlUPrCDj,eNxTuggfOBaAG,TQlUkeUqOBb) {wotCTLNlUPrCDj[eNxTuggfOBaAG]=TQlUkeUqOBb;}" fullword ascii
    $s14 = "function pASqK(urZiMCkjJqJ,PktMTJRedipQz,bxcqVRwv){RWGE=AwoFKHdmtLDXzfrYG(urZiMCkjJqJ,PktMTJRedipQz);Tpzkf=RWGE.toString(bxcqVRw" ascii
    $s15 = "function JwPaXHeURypXwJJ(jubMXGJUknKMGFdVEQy) {return parseFloat(jubMXGJUknKMGFdVEQy);}" fullword ascii
    $s16 = "v);return Tpzkf;}" fullword ascii
    $s17 = "function pASqK(urZiMCkjJqJ,PktMTJRedipQz,bxcqVRwv){RWGE=AwoFKHdmtLDXzfrYG(urZiMCkjJqJ,PktMTJRedipQz);Tpzkf=RWGE.toString(bxcqVRw" ascii
    $s18 = "function BHuOqAUbsvqC(ZIkOEORMcgQtD) {return isFinite(ZIkOEORMcgQtD);}" fullword ascii
    $s19 = "function UEGbEGKmcDg(ihOIgfnadkgYxe) {return isNaN(ihOIgfnadkgYxe);}" fullword ascii
    $s20 = "function UmgZrQBDVrrZcoV(tUOkyOTGxqmhHJxXj,yuxxVHpUnbtLzUAbnIqWsioSPBxGmMNCOr,aiaYIOQaUErfReJRkqykrmJqIqexAJpFqPz){eval(tUOkyOTG" ascii

  condition:
    uint16(0) == 0x596a and
    8 of them
}