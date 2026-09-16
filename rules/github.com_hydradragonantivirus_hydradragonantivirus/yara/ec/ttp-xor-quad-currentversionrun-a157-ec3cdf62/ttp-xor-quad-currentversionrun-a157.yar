rule TTP_XOR_QUAD_CurrentVersionRun_a157 {
  strings:
    $key_a157 = { f2 38 [2] d6 36 [2] fd 1a [2] d3 38 [2] c7 23 [2] c8 39 [2] d6 24 [2] d4 25 [2] cf 23 [2] d3 24 [2] cf 0b }

  condition:
    any of them
}