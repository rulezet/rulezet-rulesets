rule TTP_XOR_QUAD_CurrentVersionRun_3137 {
  strings:
    $key_3137 = { 62 58 [2] 46 56 [2] 6d 7a [2] 43 58 [2] 57 43 [2] 58 59 [2] 46 44 [2] 44 45 [2] 5f 43 [2] 43 44 [2] 5f 6b }

  condition:
    any of them
}