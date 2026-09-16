rule TTP_XOR_QUAD_CurrentVersionRun_7337 {
  strings:
    $key_7337 = { 20 58 [2] 04 56 [2] 2f 7a [2] 01 58 [2] 15 43 [2] 1a 59 [2] 04 44 [2] 06 45 [2] 1d 43 [2] 01 44 [2] 1d 6b }

  condition:
    any of them
}