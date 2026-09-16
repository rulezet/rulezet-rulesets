rule sig_20151209_3237a44519a1fb29202284fd82e76070 {
  meta:
    description = "datamaliciousorder - file 20151209_3237a44519a1fb29202284fd82e76070.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b61e360f13a551752dc247cf600e1ab9b29280922e437b8fcc8c0eeba2a08ae"

  strings:
    $s1  = "function pmCWCXvyVUpajqvkyRYcTBxEciHAITQDXGlWjvuIeLGeZenojgEtfU(NKQyZnUfuNGOJ,VMgAygcutarjmc){ return VCHCV[JKJOE(NKQyZnUfuNGOJ[" ascii
    $s2  = "function gnnsDKziaUlNaJsqF(GGTDz){tFwvnhyXIzr= '';for(ICjmarzQcUl=(-183+183)/232; ICjmarzQcUl < (879+173)/526; ICjmarzQcUl++) {o" ascii
    $s3  = "function pmCWCXvyVUpajqvkyRYcTBxEciHAITQDXGlWjvuIeLGeZenojgEtfU(NKQyZnUfuNGOJ,VMgAygcutarjmc){ return VCHCV[JKJOE(NKQyZnUfuNGOJ[" ascii
    $s4  = "function AXMCOdA(YUjlEEeIVOVYXaFgTyZCKEHdXZvrLFEiojTZ) {return !isNaN(parseFloat(YUjlEEeIVOVYXaFgTyZCKEHdXZvrLFEiojTZ)) && isFin" ascii
    $s5  = "function AXMCOdA(YUjlEEeIVOVYXaFgTyZCKEHdXZvrLFEiojTZ) {return !isNaN(parseFloat(YUjlEEeIVOVYXaFgTyZCKEHdXZvrLFEiojTZ)) && isFin" ascii
    $s6  = "WAygAtwU[ICjmarzQcUl]=(-816+816)/468; while(true) { if(oWAygAtwU[ICjmarzQcUl] > GGTDz[ICjmarzQcUl].length-(-637+975)/338) { brea" ascii
    $s7  = "++;}} return tFwvnhyXIzr}" fullword ascii
    $s8  = "function JKJOE(QejTJLXhuac,lfmEhvZGlrAwN,WMUbOXoq){EVKc=parseInt(QejTJLXhuac,lfmEhvZGlrAwN);SVbFd=EVKc.toString(WMUbOXoq);return" ascii
    $s9  = "function gnnsDKziaUlNaJsqF(GGTDz){tFwvnhyXIzr= '';for(ICjmarzQcUl=(-183+183)/232; ICjmarzQcUl < (879+173)/526; ICjmarzQcUl++) {o" ascii
    $s10 = "function cXWrqpYZVWv(tkvOSrNN,oUVDAB){return tkvOSrNN.split(oUVDAB)}" fullword ascii
    $s11 = "function JKJOE(QejTJLXhuac,lfmEhvZGlrAwN,WMUbOXoq){EVKc=parseInt(QejTJLXhuac,lfmEhvZGlrAwN);SVbFd=EVKc.toString(WMUbOXoq);return" ascii
    $s12 = " SVbFd;}function hQaucqlUHLWcAdu(VbbDSChQHFQBRyFmW){eval(VbbDSChQHFQBRyFmW)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}