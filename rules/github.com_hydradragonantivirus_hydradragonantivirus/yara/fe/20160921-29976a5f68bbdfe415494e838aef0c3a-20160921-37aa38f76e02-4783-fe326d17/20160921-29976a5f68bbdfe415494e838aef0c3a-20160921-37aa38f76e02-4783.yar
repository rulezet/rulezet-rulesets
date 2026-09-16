rule _20160921_29976a5f68bbdfe415494e838aef0c3a_20160921_37aa38f76e02_4783 {
  meta:
    description = "datamaliciousorder - from files 20160921_29976a5f68bbdfe415494e838aef0c3a.js, 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_77c9e00128c9a883c23909fbb2c12569.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "218bc62c15296caf93128e0a5e06fde374e19fd4150b6c9b1def4d962554ef39"
    hash2       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash3       = "95544bd07dbc8b2550e3a6bb328d49a808c8749bb3ced90cbb8f5f90782625a1"

  strings:
    $s1 = "on f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Z" ascii
    $s2 = "00(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu" ascii
    $s3 = "unction f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){retu" ascii
    $s4 = "0(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\"" ascii
    $s5 = ";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}