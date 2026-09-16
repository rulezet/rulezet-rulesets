rule TTP_XOR_QUAD_CurrentVersionRun_a147 {
  strings:
    $key_a147 = { f2 28 [2] d6 26 [2] fd 0a [2] d3 28 [2] c7 33 [2] c8 29 [2] d6 34 [2] d4 35 [2] cf 33 [2] d3 34 [2] cf 1b }

  condition:
    any of them
}