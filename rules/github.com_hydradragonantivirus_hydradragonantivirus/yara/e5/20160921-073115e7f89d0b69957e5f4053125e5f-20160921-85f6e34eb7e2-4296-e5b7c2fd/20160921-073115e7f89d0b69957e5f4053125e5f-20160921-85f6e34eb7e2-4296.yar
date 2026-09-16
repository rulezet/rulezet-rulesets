rule _20160921_073115e7f89d0b69957e5f4053125e5f_20160921_85f6e34eb7e2_4296 {
  meta:
    description = "datamaliciousorder - from files 20160921_073115e7f89d0b69957e5f4053125e5f.js, 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1c8736261480d3d6df844d8e7fb92f64f1dc2bf84561d1b707e82daa456fef1"
    hash2       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"

  strings:
    $s1 = "f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DI" ascii
    $s2 = "turn \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yz\";})(),(f" ascii
    $s3 = "})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f00" ascii
    $s4 = "00(){return \"YTp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\"" ascii
    $s5 = "turn \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}