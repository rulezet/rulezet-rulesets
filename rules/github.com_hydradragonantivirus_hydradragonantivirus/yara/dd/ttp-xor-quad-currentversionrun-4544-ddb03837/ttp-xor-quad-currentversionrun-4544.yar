rule TTP_XOR_QUAD_CurrentVersionRun_4544 {
  strings:
    $key_4544 = { 16 2b [2] 32 25 [2] 19 09 [2] 37 2b [2] 23 30 [2] 2c 2a [2] 32 37 [2] 30 36 [2] 2b 30 [2] 37 37 [2] 2b 18 }

  condition:
    any of them
}