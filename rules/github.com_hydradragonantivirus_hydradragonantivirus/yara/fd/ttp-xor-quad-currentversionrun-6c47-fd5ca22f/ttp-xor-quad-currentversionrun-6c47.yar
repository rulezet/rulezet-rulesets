rule TTP_XOR_QUAD_CurrentVersionRun_6c47 {
  strings:
    $key_6c47 = { 3f 28 [2] 1b 26 [2] 30 0a [2] 1e 28 [2] 0a 33 [2] 05 29 [2] 1b 34 [2] 19 35 [2] 02 33 [2] 1e 34 [2] 02 1b }

  condition:
    any of them
}