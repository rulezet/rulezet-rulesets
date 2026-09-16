rule TTP_XOR_QUAD_CurrentVersionRun_5537 {
  strings:
    $key_5537 = { 06 58 [2] 22 56 [2] 09 7a [2] 27 58 [2] 33 43 [2] 3c 59 [2] 22 44 [2] 20 45 [2] 3b 43 [2] 27 44 [2] 3b 6b }

  condition:
    any of them
}