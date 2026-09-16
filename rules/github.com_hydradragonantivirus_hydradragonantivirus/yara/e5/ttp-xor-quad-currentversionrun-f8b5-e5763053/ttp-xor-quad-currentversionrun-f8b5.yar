rule TTP_XOR_QUAD_CurrentVersionRun_f8b5 {
  strings:
    $key_f8b5 = { ab da [2] 8f d4 [2] a4 f8 [2] 8a da [2] 9e c1 [2] 91 db [2] 8f c6 [2] 8d c7 [2] 96 c1 [2] 8a c6 [2] 96 e9 }

  condition:
    any of them
}