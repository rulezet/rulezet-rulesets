rule TTP_XOR_QUAD_CurrentVersionRun_74e8 {
  strings:
    $key_74e8 = { 27 87 [2] 03 89 [2] 28 a5 [2] 06 87 [2] 12 9c [2] 1d 86 [2] 03 9b [2] 01 9a [2] 1a 9c [2] 06 9b [2] 1a b4 }

  condition:
    any of them
}