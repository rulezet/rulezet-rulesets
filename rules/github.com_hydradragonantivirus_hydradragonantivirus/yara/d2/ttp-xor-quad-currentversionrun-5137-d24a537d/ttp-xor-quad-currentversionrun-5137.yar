rule TTP_XOR_QUAD_CurrentVersionRun_5137 {
  strings:
    $key_5137 = { 02 58 [2] 26 56 [2] 0d 7a [2] 23 58 [2] 37 43 [2] 38 59 [2] 26 44 [2] 24 45 [2] 3f 43 [2] 23 44 [2] 3f 6b }

  condition:
    any of them
}