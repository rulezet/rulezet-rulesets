rule TTP_XOR_QUAD_CurrentVersionRun_5c06 {
  strings:
    $key_5c06 = { 0f 69 [2] 2b 67 [2] 00 4b [2] 2e 69 [2] 3a 72 [2] 35 68 [2] 2b 75 [2] 29 74 [2] 32 72 [2] 2e 75 [2] 32 5a }

  condition:
    any of them
}