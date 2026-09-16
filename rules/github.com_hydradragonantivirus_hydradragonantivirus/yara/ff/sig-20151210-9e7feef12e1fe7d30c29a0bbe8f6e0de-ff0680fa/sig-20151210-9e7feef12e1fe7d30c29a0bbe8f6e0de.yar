rule sig_20151210_9e7feef12e1fe7d30c29a0bbe8f6e0de {
  meta:
    description = "datamaliciousorder - file 20151210_9e7feef12e1fe7d30c29a0bbe8f6e0de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "854977240cefac1da2d28687c05a0e7b6f6ecebd78282240c49eae064694c5b3"

  strings:
    $s1  = "function AOOhQIf(SgdbtQHDoxireBhBiBazRQITWgNPzigVspNK) {return !isNaN(parseFloat(SgdbtQHDoxireBhBiBazRQITWgNPzigVspNK)) && isFin" ascii
    $s2  = "function AOOhQIf(SgdbtQHDoxireBhBiBazRQITWgNPzigVspNK) {return !isNaN(parseFloat(SgdbtQHDoxireBhBiBazRQITWgNPzigVspNK)) && isFin" ascii
    $s3  = "function GZFwBbVModyiyENBUzOgCXcjRdthFJjzRvihtRszmFjfHhrVPLAQTb(ytxThBGidimxo,LivGpWxzATpQfr){ return HYzLGCiufeTgk[yhmNY(ytxThB" ascii
    $s4  = "pDjeTxK=(-137+137)/844;while(true){if(pDjeTxK>=(23353+839)/189){break;}HYzLGCiufeTgk[pDjeTxK]=String.fromCharCode(pDjeTxK);pDjeT" ascii
    $s5  = "function hRFDlXScIWJ(JfzUtgwE,dsXuyo){return JfzUtgwE.split(dsXuyo)}" fullword ascii
    $s6  = "pDjeTxK=(-137+137)/844;while(true){if(pDjeTxK>=(23353+839)/189){break;}HYzLGCiufeTgk[pDjeTxK]=String.fromCharCode(pDjeTxK);pDjeT" ascii
    $s7  = "function yhmNY(XYUJtPwhMbC,WoxrSjelZNoFo,qPkaGmZh){wLal=parseInt(XYUJtPwhMbC,WoxrSjelZNoFo);jZszT=wLal.toString(qPkaGmZh);return" ascii
    $s8  = "function yhmNY(XYUJtPwhMbC,WoxrSjelZNoFo,qPkaGmZh){wLal=parseInt(XYUJtPwhMbC,WoxrSjelZNoFo);jZszT=wLal.toString(qPkaGmZh);return" ascii
    $s9  = "function huHroTWvaQoQVqrVn(AULeB){AxLDWeeeCRP= '';for(FiAkeDovfMP=(-151+151)/905; FiAkeDovfMP < (278+644)/461; FiAkeDovfMP++) {A" ascii
    $s10 = "function GZFwBbVModyiyENBUzOgCXcjRdthFJjzRvihtRszmFjfHhrVPLAQTb(ytxThBGidimxo,LivGpWxzATpQfr){ return HYzLGCiufeTgk[yhmNY(ytxThB" ascii
    $s11 = " jZszT;}function IZifOWEbfobIchq(dUDmPigtMXzunqMbk){eval(dUDmPigtMXzunqMbk)}" fullword ascii
    $s12 = "}} return AxLDWeeeCRP}" fullword ascii
    $s13 = "function huHroTWvaQoQVqrVn(AULeB){AxLDWeeeCRP= '';for(FiAkeDovfMP=(-151+151)/905; FiAkeDovfMP < (278+644)/461; FiAkeDovfMP++) {A" ascii
    $s14 = "gkQaivdV[FiAkeDovfMP]=(-629+629)/795; while(true) { if(AgkQaivdV[FiAkeDovfMP] > AULeB[FiAkeDovfMP].length-(345+248)/593) { break" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}