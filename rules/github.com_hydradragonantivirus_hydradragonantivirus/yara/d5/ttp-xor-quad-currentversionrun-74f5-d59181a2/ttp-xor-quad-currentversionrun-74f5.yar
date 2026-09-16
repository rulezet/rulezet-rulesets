rule TTP_XOR_QUAD_CurrentVersionRun_74f5 {
  strings:
    $key_74f5 = { 27 9a [2] 03 94 [2] 28 b8 [2] 06 9a [2] 12 81 [2] 1d 9b [2] 03 86 [2] 01 87 [2] 1a 81 [2] 06 86 [2] 1a a9 }

  condition:
    any of them
}