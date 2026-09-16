rule TTP_XOR_QUAD_CurrentVersionRun_3e47 {
  strings:
    $key_3e47 = { 6d 28 [2] 49 26 [2] 62 0a [2] 4c 28 [2] 58 33 [2] 57 29 [2] 49 34 [2] 4b 35 [2] 50 33 [2] 4c 34 [2] 50 1b }

  condition:
    any of them
}