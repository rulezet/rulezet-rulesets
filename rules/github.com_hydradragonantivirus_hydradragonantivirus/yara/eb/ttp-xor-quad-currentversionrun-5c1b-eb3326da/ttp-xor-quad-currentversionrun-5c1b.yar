rule TTP_XOR_QUAD_CurrentVersionRun_5c1b {
  strings:
    $key_5c1b = { 0f 74 [2] 2b 7a [2] 00 56 [2] 2e 74 [2] 3a 6f [2] 35 75 [2] 2b 68 [2] 29 69 [2] 32 6f [2] 2e 68 [2] 32 47 }

  condition:
    any of them
}