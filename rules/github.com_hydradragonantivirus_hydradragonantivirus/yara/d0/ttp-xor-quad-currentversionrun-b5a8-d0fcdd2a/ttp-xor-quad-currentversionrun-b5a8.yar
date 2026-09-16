rule TTP_XOR_QUAD_CurrentVersionRun_b5a8 {
  strings:
    $key_b5a8 = { e6 c7 [2] c2 c9 [2] e9 e5 [2] c7 c7 [2] d3 dc [2] dc c6 [2] c2 db [2] c0 da [2] db dc [2] c7 db [2] db f4 }

  condition:
    any of them
}