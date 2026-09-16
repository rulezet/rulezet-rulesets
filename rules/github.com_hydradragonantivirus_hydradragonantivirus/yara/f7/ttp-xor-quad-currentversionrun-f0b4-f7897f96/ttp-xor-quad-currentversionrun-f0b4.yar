rule TTP_XOR_QUAD_CurrentVersionRun_f0b4 {
  strings:
    $key_f0b4 = { a3 db [2] 87 d5 [2] ac f9 [2] 82 db [2] 96 c0 [2] 99 da [2] 87 c7 [2] 85 c6 [2] 9e c0 [2] 82 c7 [2] 9e e8 }

  condition:
    any of them
}