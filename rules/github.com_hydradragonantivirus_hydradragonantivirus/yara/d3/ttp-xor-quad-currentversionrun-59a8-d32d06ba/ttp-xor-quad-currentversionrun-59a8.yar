rule TTP_XOR_QUAD_CurrentVersionRun_59a8 {
  strings:
    $key_59a8 = { 0a c7 [2] 2e c9 [2] 05 e5 [2] 2b c7 [2] 3f dc [2] 30 c6 [2] 2e db [2] 2c da [2] 37 dc [2] 2b db [2] 37 f4 }

  condition:
    any of them
}