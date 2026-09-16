rule TTP_XOR_QUAD_CurrentVersionRun_1c47 {
  strings:
    $key_1c47 = { 4f 28 [2] 6b 26 [2] 40 0a [2] 6e 28 [2] 7a 33 [2] 75 29 [2] 6b 34 [2] 69 35 [2] 72 33 [2] 6e 34 [2] 72 1b }

  condition:
    any of them
}