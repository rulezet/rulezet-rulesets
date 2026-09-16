rule TTP_XOR_QUAD_CurrentVersionRun_a18e {
  strings:
    $key_a18e = { f2 e1 [2] d6 ef [2] fd c3 [2] d3 e1 [2] c7 fa [2] c8 e0 [2] d6 fd [2] d4 fc [2] cf fa [2] d3 fd [2] cf d2 }

  condition:
    any of them
}