rule TTP_XOR_QUAD_CurrentVersionRun_e3a8 {
  strings:
    $key_e3a8 = { b0 c7 [2] 94 c9 [2] bf e5 [2] 91 c7 [2] 85 dc [2] 8a c6 [2] 94 db [2] 96 da [2] 8d dc [2] 91 db [2] 8d f4 }

  condition:
    any of them
}