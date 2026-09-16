rule TTP_XOR_QUAD_CurrentVersionRun_1b47 {
  strings:
    $key_1b47 = { 48 28 [2] 6c 26 [2] 47 0a [2] 69 28 [2] 7d 33 [2] 72 29 [2] 6c 34 [2] 6e 35 [2] 75 33 [2] 69 34 [2] 75 1b }

  condition:
    any of them
}