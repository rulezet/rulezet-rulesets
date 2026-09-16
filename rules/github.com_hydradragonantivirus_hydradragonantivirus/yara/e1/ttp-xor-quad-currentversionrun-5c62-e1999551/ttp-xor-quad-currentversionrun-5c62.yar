rule TTP_XOR_QUAD_CurrentVersionRun_5c62 {
  strings:
    $key_5c62 = { 0f 0d [2] 2b 03 [2] 00 2f [2] 2e 0d [2] 3a 16 [2] 35 0c [2] 2b 11 [2] 29 10 [2] 32 16 [2] 2e 11 [2] 32 3e }

  condition:
    any of them
}