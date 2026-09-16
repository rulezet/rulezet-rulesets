rule TTP_XOR_QUAD_CurrentVersionRun_18b4 {
  strings:
    $key_18b4 = { 4b db [2] 6f d5 [2] 44 f9 [2] 6a db [2] 7e c0 [2] 71 da [2] 6f c7 [2] 6d c6 [2] 76 c0 [2] 6a c7 [2] 76 e8 }

  condition:
    any of them
}