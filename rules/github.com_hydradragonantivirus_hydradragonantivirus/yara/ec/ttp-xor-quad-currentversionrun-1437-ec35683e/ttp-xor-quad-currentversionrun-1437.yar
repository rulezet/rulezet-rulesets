rule TTP_XOR_QUAD_CurrentVersionRun_1437 {
  strings:
    $key_1437 = { 47 58 [2] 63 56 [2] 48 7a [2] 66 58 [2] 72 43 [2] 7d 59 [2] 63 44 [2] 61 45 [2] 7a 43 [2] 66 44 [2] 7a 6b }

  condition:
    any of them
}