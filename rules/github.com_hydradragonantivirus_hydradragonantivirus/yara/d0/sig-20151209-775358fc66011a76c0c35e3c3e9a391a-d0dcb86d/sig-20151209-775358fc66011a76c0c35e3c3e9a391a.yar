rule sig_20151209_775358fc66011a76c0c35e3c3e9a391a {
  meta:
    description = "datamaliciousorder - file 20151209_775358fc66011a76c0c35e3c3e9a391a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc43078524f322ecf1c2fe8c3a1c95b13a5b6a872ceb64cbc1dab7654bf03f7d"

  strings:
    $s1  = "function hKNIRFU(dmEWzGjzyhVmmugNtvcfHXjAaQorgkYluykj) {return !isNaN(parseFloat(dmEWzGjzyhVmmugNtvcfHXjAaQorgkYluykj)) && isFin" ascii
    $s2  = "function hKNIRFU(dmEWzGjzyhVmmugNtvcfHXjAaQorgkYluykj) {return !isNaN(parseFloat(dmEWzGjzyhVmmugNtvcfHXjAaQorgkYluykj)) && isFin" ascii
    $s3  = "function fKvwLypfLjV(lOWBWLfi,XxSIQx){return lOWBWLfi.split(XxSIQx)}" fullword ascii
    $s4  = "function Tbuqx(tQuafUrAAcY,aEZztDvdJRqHA,njqUHbdI){Smiu=parseInt(tQuafUrAAcY,aEZztDvdJRqHA);sGfLL=Smiu.toString(njqUHbdI);return" ascii
    $s5  = "} return DadnGdNyXoo}" fullword ascii
    $s6  = "function Tbuqx(tQuafUrAAcY,aEZztDvdJRqHA,njqUHbdI){Smiu=parseInt(tQuafUrAAcY,aEZztDvdJRqHA);sGfLL=Smiu.toString(njqUHbdI);return" ascii
    $s7  = " sGfLL;}function IGnLKCuFmlNJKMU(vLvDQwkRnPxzAeQqJ){eval(vLvDQwkRnPxzAeQqJ)}" fullword ascii
    $s8  = "function PYbQabWmnOEDmSdLa(sHHzh){DadnGdNyXoo= '';for(IfakxebICtU=(-307+307)/880; IfakxebICtU < (-577+881)/152; IfakxebICtU++) {" ascii
    $s9  = "CjURbahQe[IfakxebICtU]=(-5+5)/156; while(true) { if(CjURbahQe[IfakxebICtU] > sHHzh[IfakxebICtU].length-(541+430)/971) { break; }" ascii
    $s10 = "function iuSHBqbAldGmXQgTvktkymyeMCGHIGBCxeokGPbxbhenBQocaKwPCs(TWjfVxGBQlguD,msiIPqxrAizbjn){ return QCmne[Tbuqx(TWjfVxGBQlguD[" ascii
    $s11 = "function iuSHBqbAldGmXQgTvktkymyeMCGHIGBCxeokGPbxbhenBQocaKwPCs(TWjfVxGBQlguD,msiIPqxrAizbjn){ return QCmne[Tbuqx(TWjfVxGBQlguD[" ascii
    $s12 = "function PYbQabWmnOEDmSdLa(sHHzh){DadnGdNyXoo= '';for(IfakxebICtU=(-307+307)/880; IfakxebICtU < (-577+881)/152; IfakxebICtU++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}