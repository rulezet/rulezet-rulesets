rule TTP_XOR_QUAD_CurrentVersionRun_1077 {
  strings:
    $key_1077 = { 43 18 [2] 67 16 [2] 4c 3a [2] 62 18 [2] 76 03 [2] 79 19 [2] 67 04 [2] 65 05 [2] 7e 03 [2] 62 04 [2] 7e 2b }

  condition:
    any of them
}