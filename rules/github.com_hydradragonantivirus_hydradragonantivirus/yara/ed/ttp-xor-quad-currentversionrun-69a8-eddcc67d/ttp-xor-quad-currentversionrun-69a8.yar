rule TTP_XOR_QUAD_CurrentVersionRun_69a8 {
  strings:
    $key_69a8 = { 3a c7 [2] 1e c9 [2] 35 e5 [2] 1b c7 [2] 0f dc [2] 00 c6 [2] 1e db [2] 1c da [2] 07 dc [2] 1b db [2] 07 f4 }

  condition:
    any of them
}