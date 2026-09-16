rule TTP_XOR_QUAD_CurrentVersionRun_5147 {
  strings:
    $key_5147 = { 02 28 [2] 26 26 [2] 0d 0a [2] 23 28 [2] 37 33 [2] 38 29 [2] 26 34 [2] 24 35 [2] 3f 33 [2] 23 34 [2] 3f 1b }

  condition:
    any of them
}