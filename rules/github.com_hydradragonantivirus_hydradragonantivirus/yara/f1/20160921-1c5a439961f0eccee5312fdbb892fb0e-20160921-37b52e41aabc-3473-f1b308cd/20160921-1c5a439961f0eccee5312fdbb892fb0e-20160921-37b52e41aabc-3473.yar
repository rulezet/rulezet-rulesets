rule _20160921_1c5a439961f0eccee5312fdbb892fb0e_20160921_37b52e41aabc_3473 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_37b52e41aabc93218d864c1665a33610.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash2       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"

  strings:
    $s1 = " f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"V" ascii
    $s2 = " \"KDh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s3 = ",(function f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Vu\";})(),(function f000(){" ascii
    $s4 = "ion f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s5 = "),(function f000(){return \"Mc\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"WIj\";})(),(function f000(){" ascii
    $s6 = "return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}