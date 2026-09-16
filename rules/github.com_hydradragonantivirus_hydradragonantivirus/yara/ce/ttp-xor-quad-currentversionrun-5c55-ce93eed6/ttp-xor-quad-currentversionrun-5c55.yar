rule TTP_XOR_QUAD_CurrentVersionRun_5c55 {
  strings:
    $key_5c55 = { 0f 3a [2] 2b 34 [2] 00 18 [2] 2e 3a [2] 3a 21 [2] 35 3b [2] 2b 26 [2] 29 27 [2] 32 21 [2] 2e 26 [2] 32 09 }

  condition:
    any of them
}