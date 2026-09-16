rule TTP_XOR_QUAD_CurrentVersionRun_03a8 {
  strings:
    $key_03a8 = { 50 c7 [2] 74 c9 [2] 5f e5 [2] 71 c7 [2] 65 dc [2] 6a c6 [2] 74 db [2] 76 da [2] 6d dc [2] 71 db [2] 6d f4 }

  condition:
    any of them
}