rule TTP_XOR_QUAD_CurrentVersionRun_49a8 {
  strings:
    $key_49a8 = { 1a c7 [2] 3e c9 [2] 15 e5 [2] 3b c7 [2] 2f dc [2] 20 c6 [2] 3e db [2] 3c da [2] 27 dc [2] 3b db [2] 27 f4 }

  condition:
    any of them
}