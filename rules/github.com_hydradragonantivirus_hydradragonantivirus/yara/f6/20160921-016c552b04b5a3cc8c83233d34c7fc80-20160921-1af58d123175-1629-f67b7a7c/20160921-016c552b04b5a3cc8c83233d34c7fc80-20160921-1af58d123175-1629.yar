rule _20160921_016c552b04b5a3cc8c83233d34c7fc80_20160921_1af58d123175_1629 {
  meta:
    description = "datamaliciousorder - from files 20160921_016c552b04b5a3cc8c83233d34c7fc80.js, 20160921_1af58d1231756b320d04226685b5a131.js, 20160921_b2867778b87ab68774c77840f21eaed0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a691692f0982e93fd21c441e8c6d39328f1ea5990ce24999b2df98ee3488f667"
    hash2       = "de59166ad132c3c5ad12a85d2d837c1aec192afb497be23c517c637a08d25171"
    hash3       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"

  strings:
    $s1  = "00(){return \"Ml\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";" ascii
    $s2  = "ction f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return" ascii
    $s3  = "\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function" ascii
    $s4  = "(){return \"UEg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";" ascii
    $s5  = "\"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(funct" ascii
    $s6  = "),(function f000(){return \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qj\";})(),(function f000(){" ascii
    $s7  = "),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"KXg\";})(),(function f000()" ascii
    $s8  = "000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc" ascii
    $s9  = "{return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";}" ascii
    $s10 = "n f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Y" ascii
    $s11 = " f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}