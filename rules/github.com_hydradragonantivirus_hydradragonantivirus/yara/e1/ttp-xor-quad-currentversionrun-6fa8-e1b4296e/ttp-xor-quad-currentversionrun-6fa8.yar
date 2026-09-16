rule TTP_XOR_QUAD_CurrentVersionRun_6fa8 {
  strings:
    $key_6fa8 = { 3c c7 [2] 18 c9 [2] 33 e5 [2] 1d c7 [2] 09 dc [2] 06 c6 [2] 18 db [2] 1a da [2] 01 dc [2] 1d db [2] 01 f4 }

  condition:
    any of them
}