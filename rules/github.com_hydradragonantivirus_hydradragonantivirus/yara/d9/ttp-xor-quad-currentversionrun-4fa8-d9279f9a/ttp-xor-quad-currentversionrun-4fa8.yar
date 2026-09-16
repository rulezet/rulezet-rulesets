rule TTP_XOR_QUAD_CurrentVersionRun_4fa8 {
  strings:
    $key_4fa8 = { 1c c7 [2] 38 c9 [2] 13 e5 [2] 3d c7 [2] 29 dc [2] 26 c6 [2] 38 db [2] 3a da [2] 21 dc [2] 3d db [2] 21 f4 }

  condition:
    any of them
}