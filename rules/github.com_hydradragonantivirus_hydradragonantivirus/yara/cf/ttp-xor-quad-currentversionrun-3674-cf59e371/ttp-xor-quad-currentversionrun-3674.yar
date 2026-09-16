rule TTP_XOR_QUAD_CurrentVersionRun_3674 {
  strings:
    $key_3674 = { 65 1b [2] 41 15 [2] 6a 39 [2] 44 1b [2] 50 00 [2] 5f 1a [2] 41 07 [2] 43 06 [2] 58 00 [2] 44 07 [2] 58 28 }

  condition:
    any of them
}