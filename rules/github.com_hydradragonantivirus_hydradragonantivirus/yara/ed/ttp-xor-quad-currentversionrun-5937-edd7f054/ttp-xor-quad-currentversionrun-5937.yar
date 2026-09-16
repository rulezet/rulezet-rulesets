rule TTP_XOR_QUAD_CurrentVersionRun_5937 {
  strings:
    $key_5937 = { 0a 58 [2] 2e 56 [2] 05 7a [2] 2b 58 [2] 3f 43 [2] 30 59 [2] 2e 44 [2] 2c 45 [2] 37 43 [2] 2b 44 [2] 37 6b }

  condition:
    any of them
}