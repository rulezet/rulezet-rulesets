rule TTP_XOR_QUAD_CurrentVersionRun_7437 {
  strings:
    $key_7437 = { 27 58 [2] 03 56 [2] 28 7a [2] 06 58 [2] 12 43 [2] 1d 59 [2] 03 44 [2] 01 45 [2] 1a 43 [2] 06 44 [2] 1a 6b }

  condition:
    any of them
}