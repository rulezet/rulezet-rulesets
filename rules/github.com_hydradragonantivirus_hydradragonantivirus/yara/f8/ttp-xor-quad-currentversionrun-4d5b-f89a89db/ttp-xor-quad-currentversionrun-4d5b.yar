rule TTP_XOR_QUAD_CurrentVersionRun_4d5b {
  strings:
    $key_4d5b = { 1e 34 [2] 3a 3a [2] 11 16 [2] 3f 34 [2] 2b 2f [2] 24 35 [2] 3a 28 [2] 38 29 [2] 23 2f [2] 3f 28 [2] 23 07 }

  condition:
    any of them
}