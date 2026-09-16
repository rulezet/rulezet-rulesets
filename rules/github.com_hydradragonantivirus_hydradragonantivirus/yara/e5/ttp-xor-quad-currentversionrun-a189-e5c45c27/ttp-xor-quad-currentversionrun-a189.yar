rule TTP_XOR_QUAD_CurrentVersionRun_a189 {
  strings:
    $key_a189 = { f2 e6 [2] d6 e8 [2] fd c4 [2] d3 e6 [2] c7 fd [2] c8 e7 [2] d6 fa [2] d4 fb [2] cf fd [2] d3 fa [2] cf d5 }

  condition:
    any of them
}