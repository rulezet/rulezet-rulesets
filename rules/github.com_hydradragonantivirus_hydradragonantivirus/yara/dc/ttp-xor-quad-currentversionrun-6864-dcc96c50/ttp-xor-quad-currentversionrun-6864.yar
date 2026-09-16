rule TTP_XOR_QUAD_CurrentVersionRun_6864 {
  strings:
    $key_6864 = { 3b 0b [2] 1f 05 [2] 34 29 [2] 1a 0b [2] 0e 10 [2] 01 0a [2] 1f 17 [2] 1d 16 [2] 06 10 [2] 1a 17 [2] 06 38 }

  condition:
    any of them
}