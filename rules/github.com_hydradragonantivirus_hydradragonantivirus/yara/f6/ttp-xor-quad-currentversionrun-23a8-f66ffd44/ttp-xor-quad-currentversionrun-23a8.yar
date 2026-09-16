rule TTP_XOR_QUAD_CurrentVersionRun_23a8 {
  strings:
    $key_23a8 = { 70 c7 [2] 54 c9 [2] 7f e5 [2] 51 c7 [2] 45 dc [2] 4a c6 [2] 54 db [2] 56 da [2] 4d dc [2] 51 db [2] 4d f4 }

  condition:
    any of them
}