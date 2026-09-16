rule TTP_XOR_QUAD_CurrentVersionRun_5c25 {
  strings:
    $key_5c25 = { 0f 4a [2] 2b 44 [2] 00 68 [2] 2e 4a [2] 3a 51 [2] 35 4b [2] 2b 56 [2] 29 57 [2] 32 51 [2] 2e 56 [2] 32 79 }

  condition:
    any of them
}