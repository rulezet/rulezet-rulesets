rule TTP_XOR_QUAD_CurrentVersionRun_5c19 {
  strings:
    $key_5c19 = { 0f 76 [2] 2b 78 [2] 00 54 [2] 2e 76 [2] 3a 6d [2] 35 77 [2] 2b 6a [2] 29 6b [2] 32 6d [2] 2e 6a [2] 32 45 }

  condition:
    any of them
}