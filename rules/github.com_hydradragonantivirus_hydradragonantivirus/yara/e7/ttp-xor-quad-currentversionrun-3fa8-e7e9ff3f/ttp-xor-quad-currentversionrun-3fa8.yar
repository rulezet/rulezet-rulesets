rule TTP_XOR_QUAD_CurrentVersionRun_3fa8 {
  strings:
    $key_3fa8 = { 6c c7 [2] 48 c9 [2] 63 e5 [2] 4d c7 [2] 59 dc [2] 56 c6 [2] 48 db [2] 4a da [2] 51 dc [2] 4d db [2] 51 f4 }

  condition:
    any of them
}