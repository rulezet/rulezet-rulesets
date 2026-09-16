rule _20160921_37aa38f76e02afb64903280105ce4597_20160921_d1c97b87a698_3629 {
  meta:
    description = "datamaliciousorder - from files 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = "Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s2 = "Rc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(functio" ascii
    $s3 = "n \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s4 = "ction f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"NBs\";})(),(function f000(){retu" ascii
    $s5 = "nction f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s6 = "nction f000(){return \"Vj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}