rule TTP_XOR_QUAD_CurrentVersionRun_73f5 {
  strings:
    $key_73f5 = { 20 9a [2] 04 94 [2] 2f b8 [2] 01 9a [2] 15 81 [2] 1a 9b [2] 04 86 [2] 06 87 [2] 1d 81 [2] 01 86 [2] 1d a9 }

  condition:
    any of them
}