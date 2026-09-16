rule TTP_XOR_QUAD_CurrentVersionRun_1f77 {
  strings:
    $key_1f77 = { 4c 18 [2] 68 16 [2] 43 3a [2] 6d 18 [2] 79 03 [2] 76 19 [2] 68 04 [2] 6a 05 [2] 71 03 [2] 6d 04 [2] 71 2b }

  condition:
    any of them
}