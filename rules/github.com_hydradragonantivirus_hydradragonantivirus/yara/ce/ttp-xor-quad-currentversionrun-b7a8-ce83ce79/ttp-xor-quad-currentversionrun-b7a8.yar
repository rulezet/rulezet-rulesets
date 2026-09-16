rule TTP_XOR_QUAD_CurrentVersionRun_b7a8 {
  strings:
    $key_b7a8 = { e4 c7 [2] c0 c9 [2] eb e5 [2] c5 c7 [2] d1 dc [2] de c6 [2] c0 db [2] c2 da [2] d9 dc [2] c5 db [2] d9 f4 }

  condition:
    any of them
}