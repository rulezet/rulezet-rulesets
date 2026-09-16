rule TTP_XOR_QUAD_CurrentVersionRun_a123 {
  strings:
    $key_a123 = { f2 4c [2] d6 42 [2] fd 6e [2] d3 4c [2] c7 57 [2] c8 4d [2] d6 50 [2] d4 51 [2] cf 57 [2] d3 50 [2] cf 7f }

  condition:
    any of them
}