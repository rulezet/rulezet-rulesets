rule TTP_XOR_QUAD_CurrentVersionRun_4796 {
  strings:
    $key_4796 = { 14 f9 [2] 30 f7 [2] 1b db [2] 35 f9 [2] 21 e2 [2] 2e f8 [2] 30 e5 [2] 32 e4 [2] 29 e2 [2] 35 e5 [2] 29 ca }

  condition:
    any of them
}