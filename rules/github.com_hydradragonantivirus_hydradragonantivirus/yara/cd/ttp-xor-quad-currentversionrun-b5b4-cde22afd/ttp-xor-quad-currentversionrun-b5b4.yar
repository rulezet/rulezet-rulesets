rule TTP_XOR_QUAD_CurrentVersionRun_b5b4 {
  strings:
    $key_b5b4 = { e6 db [2] c2 d5 [2] e9 f9 [2] c7 db [2] d3 c0 [2] dc da [2] c2 c7 [2] c0 c6 [2] db c0 [2] c7 c7 [2] db e8 }

  condition:
    any of them
}