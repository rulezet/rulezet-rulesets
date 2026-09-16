rule TTP_XOR_QUAD_CurrentVersionRun_5a37 {
  strings:
    $key_5a37 = { 09 58 [2] 2d 56 [2] 06 7a [2] 28 58 [2] 3c 43 [2] 33 59 [2] 2d 44 [2] 2f 45 [2] 34 43 [2] 28 44 [2] 34 6b }

  condition:
    any of them
}