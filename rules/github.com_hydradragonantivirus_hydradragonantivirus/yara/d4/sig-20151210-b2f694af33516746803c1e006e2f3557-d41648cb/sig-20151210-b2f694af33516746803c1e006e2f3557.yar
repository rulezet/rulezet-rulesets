rule sig_20151210_b2f694af33516746803c1e006e2f3557 {
  meta:
    description = "datamaliciousorder - file 20151210_b2f694af33516746803c1e006e2f3557.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "385ab46d8e983067df461c9f2a960a1c0f32d9759eacd288fbcbfd02eefc842a"

  strings:
    $s1  = "function ASJuNwq(uXltEvYGnPCMCdwGjTADySGphMqkqLHLEFpW) {return !isNaN(parseFloat(uXltEvYGnPCMCdwGjTADySGphMqkqLHLEFpW)) && isFin" ascii
    $s2  = "function ASJuNwq(uXltEvYGnPCMCdwGjTADySGphMqkqLHLEFpW) {return !isNaN(parseFloat(uXltEvYGnPCMCdwGjTADySGphMqkqLHLEFpW)) && isFin" ascii
    $s3  = "function OYOhITDatYr(QuDOOyQZ,nXWhhJ){return QuDOOyQZ.split(nXWhhJ)}" fullword ascii
    $s4  = "gYzYiXb=(-562+562)/976;while(true){if(gYzYiXb>=(79756+884)/630){break;}hhaGHOoTZOrGO[gYzYiXb]=String.fromCharCode(gYzYiXb);gYzYi" ascii
    $s5  = "function lGFWNZEmxWVYXYpeInwIczNAiwvPTuvlOxBjmGipwkwobODedHwehG(pctqdoTQKNQlE,MXTMkOBJguauau){ return hhaGHOoTZOrGO[JyZKW(pctqdo" ascii
    $s6  = "gYzYiXb=(-562+562)/976;while(true){if(gYzYiXb>=(79756+884)/630){break;}hhaGHOoTZOrGO[gYzYiXb]=String.fromCharCode(gYzYiXb);gYzYi" ascii
    $s7  = "function JyZKW(lWhWaPXrbUJ,XRjNnkZXmXOzL,BatOeQpO){vbPK=parseInt(lWhWaPXrbUJ,XRjNnkZXmXOzL);bsntl=vbPK.toString(BatOeQpO);return" ascii
    $s8  = "function risXNbaeAbymDcDVt(MoOjB){ojBaaPuIKrZ= '';for(iyKNGpCdbfk=(-95+95)/940; iyKNGpCdbfk < (-807+875)/34; iyKNGpCdbfk++) {xvP" ascii
    $s9  = "function lGFWNZEmxWVYXYpeInwIczNAiwvPTuvlOxBjmGipwkwobODedHwehG(pctqdoTQKNQlE,MXTMkOBJguauau){ return hhaGHOoTZOrGO[JyZKW(pctqdo" ascii
    $s10 = "function risXNbaeAbymDcDVt(MoOjB){ojBaaPuIKrZ= '';for(iyKNGpCdbfk=(-95+95)/940; iyKNGpCdbfk < (-807+875)/34; iyKNGpCdbfk++) {xvP" ascii
    $s11 = "function JyZKW(lWhWaPXrbUJ,XRjNnkZXmXOzL,BatOeQpO){vbPK=parseInt(lWhWaPXrbUJ,XRjNnkZXmXOzL);bsntl=vbPK.toString(BatOeQpO);return" ascii
    $s12 = "wawLbq[iyKNGpCdbfk]=(-963+963)/813; while(true) { if(xvPwawLbq[iyKNGpCdbfk] > MoOjB[iyKNGpCdbfk].length-(314+24)/338) { break; }" ascii
    $s13 = "} return ojBaaPuIKrZ}" fullword ascii
    $s14 = " bsntl;}function gDtjVHiORbfcbFg(ozaeETIYTJIJWrHVZ){eval(ozaeETIYTJIJWrHVZ)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}