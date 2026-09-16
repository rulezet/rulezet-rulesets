rule TTP_XOR_QUAD_CurrentVersionRun_b5b7 {
  strings:
    $key_b5b7 = { e6 d8 [2] c2 d6 [2] e9 fa [2] c7 d8 [2] d3 c3 [2] dc d9 [2] c2 c4 [2] c0 c5 [2] db c3 [2] c7 c4 [2] db eb }

  condition:
    any of them
}