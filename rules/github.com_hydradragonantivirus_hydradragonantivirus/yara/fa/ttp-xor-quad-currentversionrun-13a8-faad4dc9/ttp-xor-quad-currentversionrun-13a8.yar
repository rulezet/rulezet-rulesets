rule TTP_XOR_QUAD_CurrentVersionRun_13a8 {
  strings:
    $key_13a8 = { 40 c7 [2] 64 c9 [2] 4f e5 [2] 61 c7 [2] 75 dc [2] 7a c6 [2] 64 db [2] 66 da [2] 7d dc [2] 61 db [2] 7d f4 }

  condition:
    any of them
}