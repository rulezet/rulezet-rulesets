rule TTP_XOR_QUAD_CurrentVersionRun_f9b4 {
  strings:
    $key_f9b4 = { aa db [2] 8e d5 [2] a5 f9 [2] 8b db [2] 9f c0 [2] 90 da [2] 8e c7 [2] 8c c6 [2] 97 c0 [2] 8b c7 [2] 97 e8 }

  condition:
    any of them
}