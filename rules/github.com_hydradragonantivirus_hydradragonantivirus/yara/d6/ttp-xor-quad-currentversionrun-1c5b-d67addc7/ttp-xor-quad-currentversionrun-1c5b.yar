rule TTP_XOR_QUAD_CurrentVersionRun_1c5b {
  strings:
    $key_1c5b = { 4f 34 [2] 6b 3a [2] 40 16 [2] 6e 34 [2] 7a 2f [2] 75 35 [2] 6b 28 [2] 69 29 [2] 72 2f [2] 6e 28 [2] 72 07 }

  condition:
    any of them
}