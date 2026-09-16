rule TTP_XOR_QUAD_CurrentVersionRun_5c07 {
  strings:
    $key_5c07 = { 0f 68 [2] 2b 66 [2] 00 4a [2] 2e 68 [2] 3a 73 [2] 35 69 [2] 2b 74 [2] 29 75 [2] 32 73 [2] 2e 74 [2] 32 5b }

  condition:
    any of them
}