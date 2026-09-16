rule TTP_XOR_QUAD_CurrentVersionRun_4096 {
  strings:
    $key_4096 = { 13 f9 [2] 37 f7 [2] 1c db [2] 32 f9 [2] 26 e2 [2] 29 f8 [2] 37 e5 [2] 35 e4 [2] 2e e2 [2] 32 e5 [2] 2e ca }

  condition:
    any of them
}