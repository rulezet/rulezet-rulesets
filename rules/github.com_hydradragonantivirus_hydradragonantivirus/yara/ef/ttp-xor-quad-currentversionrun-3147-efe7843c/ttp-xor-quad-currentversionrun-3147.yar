rule TTP_XOR_QUAD_CurrentVersionRun_3147 {
  strings:
    $key_3147 = { 62 28 [2] 46 26 [2] 6d 0a [2] 43 28 [2] 57 33 [2] 58 29 [2] 46 34 [2] 44 35 [2] 5f 33 [2] 43 34 [2] 5f 1b }

  condition:
    any of them
}