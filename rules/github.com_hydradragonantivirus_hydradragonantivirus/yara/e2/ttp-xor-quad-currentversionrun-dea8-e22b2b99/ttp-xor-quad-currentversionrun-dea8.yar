rule TTP_XOR_QUAD_CurrentVersionRun_dea8 {
  strings:
    $key_dea8 = { 8d c7 [2] a9 c9 [2] 82 e5 [2] ac c7 [2] b8 dc [2] b7 c6 [2] a9 db [2] ab da [2] b0 dc [2] ac db [2] b0 f4 }

  condition:
    any of them
}