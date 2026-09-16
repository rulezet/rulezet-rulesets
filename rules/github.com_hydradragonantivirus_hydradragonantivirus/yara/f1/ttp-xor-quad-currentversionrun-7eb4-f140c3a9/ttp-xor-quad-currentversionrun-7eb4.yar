rule TTP_XOR_QUAD_CurrentVersionRun_7eb4 {
  strings:
    $key_7eb4 = { 2d db [2] 09 d5 [2] 22 f9 [2] 0c db [2] 18 c0 [2] 17 da [2] 09 c7 [2] 0b c6 [2] 10 c0 [2] 0c c7 [2] 10 e8 }

  condition:
    any of them
}