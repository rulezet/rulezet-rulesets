rule _20160921_68e1fc90afca497654d8f771197c2097_20160921_ea3000546b29_5342 {
  meta:
    description = "datamaliciousorder - from files 20160921_68e1fc90afca497654d8f771197c2097.js, 20160921_ea3000546b29aee563be9d58318d1857.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"
    hash2       = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"

  strings:
    $s1 = " \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s2 = "n f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"G" ascii
    $s3 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Oh\";})(),(function f000(){" ascii
    $s4 = " f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s5 = "00(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}