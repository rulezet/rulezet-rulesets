rule _20160921_0fe6501a0417801a0e1868963016e9be_20160921_ea3000546b29_4375 {
  meta:
    description = "datamaliciousorder - from files 20160921_0fe6501a0417801a0e1868963016e9be.js, 20160921_ea3000546b29aee563be9d58318d1857.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2926229ccbf6b86ba0ed1aa3ab5b137a43467ffe25d09479a7998c2fdc4b2b30"
    hash2       = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"

  strings:
    $s1 = "n \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(func" ascii
    $s2 = "(function f000(){return \"Tb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s3 = "nction f000(){return \"Yz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){retu" ascii
    $s4 = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"UEg\";})(),(functi" ascii
    $s5 = "turn \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}