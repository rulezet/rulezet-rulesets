rule TTP_XOR_QUAD_CurrentVersionRun_1cb4 {
  strings:
    $key_1cb4 = { 4f db [2] 6b d5 [2] 40 f9 [2] 6e db [2] 7a c0 [2] 75 da [2] 6b c7 [2] 69 c6 [2] 72 c0 [2] 6e c7 [2] 72 e8 }

  condition:
    any of them
}