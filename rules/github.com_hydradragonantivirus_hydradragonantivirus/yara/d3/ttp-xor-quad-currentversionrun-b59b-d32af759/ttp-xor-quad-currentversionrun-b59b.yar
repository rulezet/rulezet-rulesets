rule TTP_XOR_QUAD_CurrentVersionRun_b59b {
  strings:
    $key_b59b = { e6 f4 [2] c2 fa [2] e9 d6 [2] c7 f4 [2] d3 ef [2] dc f5 [2] c2 e8 [2] c0 e9 [2] db ef [2] c7 e8 [2] db c7 }

  condition:
    any of them
}