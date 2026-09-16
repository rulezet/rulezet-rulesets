rule TTP_XOR_QUAD_CurrentVersionRun_a69b {
  strings:
    $key_a69b = { f5 f4 [2] d1 fa [2] fa d6 [2] d4 f4 [2] c0 ef [2] cf f5 [2] d1 e8 [2] d3 e9 [2] c8 ef [2] d4 e8 [2] c8 c7 }

  condition:
    any of them
}