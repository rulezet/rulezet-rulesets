rule TTP_XOR_QUAD_CurrentVersionRun_5cf5 {
  strings:
    $key_5cf5 = { 0f 9a [2] 2b 94 [2] 00 b8 [2] 2e 9a [2] 3a 81 [2] 35 9b [2] 2b 86 [2] 29 87 [2] 32 81 [2] 2e 86 [2] 32 a9 }

  condition:
    any of them
}