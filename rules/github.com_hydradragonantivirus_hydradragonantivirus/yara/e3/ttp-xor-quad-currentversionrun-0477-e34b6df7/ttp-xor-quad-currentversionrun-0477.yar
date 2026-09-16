rule TTP_XOR_QUAD_CurrentVersionRun_0477 {
  strings:
    $key_0477 = { 57 18 [2] 73 16 [2] 58 3a [2] 76 18 [2] 62 03 [2] 6d 19 [2] 73 04 [2] 71 05 [2] 6a 03 [2] 76 04 [2] 6a 2b }

  condition:
    any of them
}