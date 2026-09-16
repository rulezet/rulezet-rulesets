rule TTP_XOR_QUAD_CurrentVersionRun_5c2b {
  strings:
    $key_5c2b = { 0f 44 [2] 2b 4a [2] 00 66 [2] 2e 44 [2] 3a 5f [2] 35 45 [2] 2b 58 [2] 29 59 [2] 32 5f [2] 2e 58 [2] 32 77 }

  condition:
    any of them
}