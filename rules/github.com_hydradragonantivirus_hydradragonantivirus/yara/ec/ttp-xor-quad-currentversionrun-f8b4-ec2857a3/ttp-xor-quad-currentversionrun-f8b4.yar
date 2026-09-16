rule TTP_XOR_QUAD_CurrentVersionRun_f8b4 {
  strings:
    $key_f8b4 = { ab db [2] 8f d5 [2] a4 f9 [2] 8a db [2] 9e c0 [2] 91 da [2] 8f c7 [2] 8d c6 [2] 96 c0 [2] 8a c7 [2] 96 e8 }

  condition:
    any of them
}