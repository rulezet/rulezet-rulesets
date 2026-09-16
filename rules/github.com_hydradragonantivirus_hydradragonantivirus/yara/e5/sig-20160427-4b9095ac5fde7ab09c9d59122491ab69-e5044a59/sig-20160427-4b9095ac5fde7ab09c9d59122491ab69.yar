rule sig_20160427_4b9095ac5fde7ab09c9d59122491ab69 {
  meta:
    description = "datamaliciousorder - file 20160427_4b9095ac5fde7ab09c9d59122491ab69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fce34495437dea30076cda45a975738ac62b13190078a296d3ac1968158cf83"

  strings:
    $s1  = " var PPb = 57;var BnCYSK = 7529;var kfxagx = 5562;PPb = BnCYSK + kfxagx;var ModE = 6488;ModE = 4261 + 3192;BnCYSK = 8650 + 4090;" ascii
    $s2  = " if(5 === true) {" fullword ascii
    $s3  = " if(5 == false) {" fullword ascii
    $s4  = " if(6 == true) {" fullword ascii
    $s5  = "switch(4) {" fullword ascii
    $s6  = "switch(false) {" fullword ascii
    $s7  = "}switch(5) {" fullword ascii
    $s8  = "return 1;}function iHO () {" fullword ascii
    $s9  = "function rVrI () {" fullword ascii
    $s10 = " var iZwyq = false; " fullword ascii
    $s11 = "switch(\"zsLWZpN\") {" fullword ascii
    $s12 = " var pLriIJ = 75474; switch(true) {" fullword ascii
    $s13 = " var faIaq = false; " fullword ascii
    $s14 = "}return false;}try{if(vcnsjHK(1,\"wkXokP\",true) == 1) { if(QlsrLeo(1) != true) { if(VwaLdE(false,1) == false) { if(YRqctq(1,1) " ascii
    $s15 = "function jOSw (niODoGqO,VaaPgS) {" fullword ascii
    $s16 = "function Iad () {" fullword ascii
    $s17 = "function lRBdPIt (YAhBq,xMaU) {" fullword ascii
    $s18 = "} var xAjAUe = true; " fullword ascii
    $s19 = "}function VwaLdE (PIXE,xaMuNk) {" fullword ascii
    $s20 = "function DtazsIH () {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}