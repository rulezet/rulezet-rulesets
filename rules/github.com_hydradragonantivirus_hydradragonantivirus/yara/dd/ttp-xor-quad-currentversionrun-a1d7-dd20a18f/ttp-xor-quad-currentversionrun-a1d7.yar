rule TTP_XOR_QUAD_CurrentVersionRun_a1d7 {
  strings:
    $key_a1d7 = { f2 b8 [2] d6 b6 [2] fd 9a [2] d3 b8 [2] c7 a3 [2] c8 b9 [2] d6 a4 [2] d4 a5 [2] cf a3 [2] d3 a4 [2] cf 8b }

  condition:
    any of them
}