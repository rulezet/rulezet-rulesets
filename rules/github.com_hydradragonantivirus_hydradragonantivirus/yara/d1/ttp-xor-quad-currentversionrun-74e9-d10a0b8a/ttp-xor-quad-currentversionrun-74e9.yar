rule TTP_XOR_QUAD_CurrentVersionRun_74e9 {
  strings:
    $key_74e9 = { 27 86 [2] 03 88 [2] 28 a4 [2] 06 86 [2] 12 9d [2] 1d 87 [2] 03 9a [2] 01 9b [2] 1a 9d [2] 06 9a [2] 1a b5 }

  condition:
    any of them
}