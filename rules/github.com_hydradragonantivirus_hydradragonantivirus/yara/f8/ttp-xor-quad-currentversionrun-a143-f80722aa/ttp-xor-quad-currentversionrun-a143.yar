rule TTP_XOR_QUAD_CurrentVersionRun_a143 {
  strings:
    $key_a143 = { f2 2c [2] d6 22 [2] fd 0e [2] d3 2c [2] c7 37 [2] c8 2d [2] d6 30 [2] d4 31 [2] cf 37 [2] d3 30 [2] cf 1f }

  condition:
    any of them
}