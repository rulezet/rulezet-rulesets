rule TTP_XOR_QUAD_CurrentVersionRun_6047 {
  strings:
    $key_6047 = { 33 28 [2] 17 26 [2] 3c 0a [2] 12 28 [2] 06 33 [2] 09 29 [2] 17 34 [2] 15 35 [2] 0e 33 [2] 12 34 [2] 0e 1b }

  condition:
    any of them
}