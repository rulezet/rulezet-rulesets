rule TTP_XOR_QUAD_CurrentVersionRun_63b4 {
  strings:
    $key_63b4 = { 30 db [2] 14 d5 [2] 3f f9 [2] 11 db [2] 05 c0 [2] 0a da [2] 14 c7 [2] 16 c6 [2] 0d c0 [2] 11 c7 [2] 0d e8 }

  condition:
    any of them
}