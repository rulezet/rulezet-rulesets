rule TTP_XOR_QUAD_CurrentVersionRun_1247 {
  strings:
    $key_1247 = { 41 28 [2] 65 26 [2] 4e 0a [2] 60 28 [2] 74 33 [2] 7b 29 [2] 65 34 [2] 67 35 [2] 7c 33 [2] 60 34 [2] 7c 1b }

  condition:
    any of them
}