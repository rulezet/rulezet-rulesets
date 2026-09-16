rule TTP_XOR_QUAD_CurrentVersionRun_1fb4 {
  strings:
    $key_1fb4 = { 4c db [2] 68 d5 [2] 43 f9 [2] 6d db [2] 79 c0 [2] 76 da [2] 68 c7 [2] 6a c6 [2] 71 c0 [2] 6d c7 [2] 71 e8 }

  condition:
    any of them
}