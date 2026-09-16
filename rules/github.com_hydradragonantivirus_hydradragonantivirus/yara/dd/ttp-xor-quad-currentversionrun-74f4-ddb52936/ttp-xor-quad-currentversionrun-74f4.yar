rule TTP_XOR_QUAD_CurrentVersionRun_74f4 {
  strings:
    $key_74f4 = { 27 9b [2] 03 95 [2] 28 b9 [2] 06 9b [2] 12 80 [2] 1d 9a [2] 03 87 [2] 01 86 [2] 1a 80 [2] 06 87 [2] 1a a8 }

  condition:
    any of them
}