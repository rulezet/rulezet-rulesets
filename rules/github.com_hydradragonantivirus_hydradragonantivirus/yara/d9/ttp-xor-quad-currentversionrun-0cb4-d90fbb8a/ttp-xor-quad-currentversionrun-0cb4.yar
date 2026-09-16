rule TTP_XOR_QUAD_CurrentVersionRun_0cb4 {
  strings:
    $key_0cb4 = { 5f db [2] 7b d5 [2] 50 f9 [2] 7e db [2] 6a c0 [2] 65 da [2] 7b c7 [2] 79 c6 [2] 62 c0 [2] 7e c7 [2] 62 e8 }

  condition:
    any of them
}