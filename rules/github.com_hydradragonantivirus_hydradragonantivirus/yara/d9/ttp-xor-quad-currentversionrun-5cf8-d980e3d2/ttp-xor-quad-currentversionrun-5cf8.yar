rule TTP_XOR_QUAD_CurrentVersionRun_5cf8 {
  strings:
    $key_5cf8 = { 0f 97 [2] 2b 99 [2] 00 b5 [2] 2e 97 [2] 3a 8c [2] 35 96 [2] 2b 8b [2] 29 8a [2] 32 8c [2] 2e 8b [2] 32 a4 }

  condition:
    any of them
}