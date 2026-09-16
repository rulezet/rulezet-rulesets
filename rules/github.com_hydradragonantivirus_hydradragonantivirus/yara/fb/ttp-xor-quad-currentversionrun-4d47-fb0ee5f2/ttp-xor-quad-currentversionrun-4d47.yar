rule TTP_XOR_QUAD_CurrentVersionRun_4d47 {
  strings:
    $key_4d47 = { 1e 28 [2] 3a 26 [2] 11 0a [2] 3f 28 [2] 2b 33 [2] 24 29 [2] 3a 34 [2] 38 35 [2] 23 33 [2] 3f 34 [2] 23 1b }

  condition:
    any of them
}