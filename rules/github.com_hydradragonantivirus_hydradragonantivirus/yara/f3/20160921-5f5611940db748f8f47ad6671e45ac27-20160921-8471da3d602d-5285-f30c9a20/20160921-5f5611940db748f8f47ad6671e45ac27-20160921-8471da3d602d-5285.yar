rule _20160921_5f5611940db748f8f47ad6671e45ac27_20160921_8471da3d602d_5285 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash2       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"

  strings:
    $s1 = "(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";}" ascii
    $s2 = "on f000(){return \"DNa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s3 = "tion f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii
    $s4 = "function f000(){return \"TRc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OMd\";})(),(function f000(){r" ascii
    $s5 = "\"GGn\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"BQb\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}