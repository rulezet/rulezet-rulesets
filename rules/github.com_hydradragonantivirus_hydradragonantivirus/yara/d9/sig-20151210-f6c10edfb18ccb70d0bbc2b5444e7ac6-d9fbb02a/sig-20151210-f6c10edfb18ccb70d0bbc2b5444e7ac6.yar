rule sig_20151210_f6c10edfb18ccb70d0bbc2b5444e7ac6 {
  meta:
    description = "datamaliciousorder - file 20151210_f6c10edfb18ccb70d0bbc2b5444e7ac6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad0f047b43abbf8fa681a4173ef117c56889079c606bb0b419435c0906f8a04f"

  strings:
    $s1  = "function KMzeL(hYPTopRNnYc,pHnqSOAUGrTAv,VOZoYDZE){loGB=parseInt(hYPTopRNnYc,pHnqSOAUGrTAv);fSLFy=loGB.toString(VOZoYDZE);return" ascii
    $s2  = "function KMzeL(hYPTopRNnYc,pHnqSOAUGrTAv,VOZoYDZE){loGB=parseInt(hYPTopRNnYc,pHnqSOAUGrTAv);fSLFy=loGB.toString(VOZoYDZE);return" ascii
    $s3  = "function bxVZsPH(rueFcOYCJEemdXhZYqupkjzigpMVpHJkwGDh) {return !isNaN(parseFloat(rueFcOYCJEemdXhZYqupkjzigpMVpHJkwGDh)) && isFin" ascii
    $s4  = "function bxVZsPH(rueFcOYCJEemdXhZYqupkjzigpMVpHJkwGDh) {return !isNaN(parseFloat(rueFcOYCJEemdXhZYqupkjzigpMVpHJkwGDh)) && isFin" ascii
    $s5  = "function LAFGNhjHnzYrZLgUiKFyLcgmBTvMPZGvbquwYQXiRjWzChvVJPgxan(ioUMXkbhJNasN,rSCJinvCKwjcXQ){ return NJhzMfxAQtBHr[KMzeL(ioUMXk" ascii
    $s6  = " fSLFy;}function EXoEVwUFcwKGpMp(BGOlxlFBvzOZHNehO){eval(BGOlxlFBvzOZHNehO)}" fullword ascii
    $s7  = "+;}} return dzeEZHlFAov}" fullword ascii
    $s8  = "rActRjd=(-202+202)/596;while(true){if(rActRjd>=(27099+293)/214){break;}NJhzMfxAQtBHr[rActRjd]=String.fromCharCode(rActRjd);rActR" ascii
    $s9  = "function XuXrBCCdHiHVgrbue(dcGGf){dzeEZHlFAov= '';for(ISBYSVxIJjj=(-803+803)/71; ISBYSVxIJjj < (460+658)/559; ISBYSVxIJjj++) {Ha" ascii
    $s10 = "uzfNouZ[ISBYSVxIJjj]=(-122+122)/318; while(true) { if(HauzfNouZ[ISBYSVxIJjj] > dcGGf[ISBYSVxIJjj].length-(636+350)/986) { break;" ascii
    $s11 = "function KhjncIhMVWU(cbzIgicD,RBwrHL){return cbzIgicD.split(RBwrHL)}" fullword ascii
    $s12 = "function XuXrBCCdHiHVgrbue(dcGGf){dzeEZHlFAov= '';for(ISBYSVxIJjj=(-803+803)/71; ISBYSVxIJjj < (460+658)/559; ISBYSVxIJjj++) {Ha" ascii
    $s13 = "function LAFGNhjHnzYrZLgUiKFyLcgmBTvMPZGvbquwYQXiRjWzChvVJPgxan(ioUMXkbhJNasN,rSCJinvCKwjcXQ){ return NJhzMfxAQtBHr[KMzeL(ioUMXk" ascii
    $s14 = "rActRjd=(-202+202)/596;while(true){if(rActRjd>=(27099+293)/214){break;}NJhzMfxAQtBHr[rActRjd]=String.fromCharCode(rActRjd);rActR" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}