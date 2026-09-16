rule TTP_XOR_QUAD_CurrentVersionRun_09b4 {
  strings:
    $key_09b4 = { 5a db [2] 7e d5 [2] 55 f9 [2] 7b db [2] 6f c0 [2] 60 da [2] 7e c7 [2] 7c c6 [2] 67 c0 [2] 7b c7 [2] 67 e8 }

  condition:
    any of them
}