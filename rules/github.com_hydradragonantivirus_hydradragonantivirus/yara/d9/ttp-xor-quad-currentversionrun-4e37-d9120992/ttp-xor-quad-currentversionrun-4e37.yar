rule TTP_XOR_QUAD_CurrentVersionRun_4e37 {
  strings:
    $key_4e37 = { 1d 58 [2] 39 56 [2] 12 7a [2] 3c 58 [2] 28 43 [2] 27 59 [2] 39 44 [2] 3b 45 [2] 20 43 [2] 3c 44 [2] 20 6b }

  condition:
    any of them
}