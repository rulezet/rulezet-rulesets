rule _20160921_975c5c13ffec0e2608898a142a2baed7_20160921_b32c8921e339_5569 {
  meta:
    description = "datamaliciousorder - from files 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js, 20160921_f1cc02f488792b7161849f8d15549315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash2       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"
    hash3       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"

  strings:
    $s1 = "on f000(){return \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"G" ascii
    $s2 = "n f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"OM" ascii
    $s3 = "urn \"YTp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})()," ascii
    $s4 = "rn \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s5 = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Nx" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}