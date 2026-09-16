rule TTP_XOR_QUAD_CurrentVersionRun_4777 {
  strings:
    $key_4777 = { 14 18 [2] 30 16 [2] 1b 3a [2] 35 18 [2] 21 03 [2] 2e 19 [2] 30 04 [2] 32 05 [2] 29 03 [2] 35 04 [2] 29 2b }

  condition:
    any of them
}