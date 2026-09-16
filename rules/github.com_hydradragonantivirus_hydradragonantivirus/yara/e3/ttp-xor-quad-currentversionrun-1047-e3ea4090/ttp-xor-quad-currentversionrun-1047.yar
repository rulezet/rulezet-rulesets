rule TTP_XOR_QUAD_CurrentVersionRun_1047 {
  strings:
    $key_1047 = { 43 28 [2] 67 26 [2] 4c 0a [2] 62 28 [2] 76 33 [2] 79 29 [2] 67 34 [2] 65 35 [2] 7e 33 [2] 62 34 [2] 7e 1b }

  condition:
    any of them
}