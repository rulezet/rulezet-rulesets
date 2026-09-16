rule TTP_XOR_QUAD_CurrentVersionRun_0b47 {
  strings:
    $key_0b47 = { 58 28 [2] 7c 26 [2] 57 0a [2] 79 28 [2] 6d 33 [2] 62 29 [2] 7c 34 [2] 7e 35 [2] 65 33 [2] 79 34 [2] 65 1b }

  condition:
    any of them
}