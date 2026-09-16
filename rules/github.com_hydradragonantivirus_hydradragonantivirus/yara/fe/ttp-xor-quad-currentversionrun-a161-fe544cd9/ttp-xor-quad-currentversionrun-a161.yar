rule TTP_XOR_QUAD_CurrentVersionRun_a161 {
  strings:
    $key_a161 = { f2 0e [2] d6 00 [2] fd 2c [2] d3 0e [2] c7 15 [2] c8 0f [2] d6 12 [2] d4 13 [2] cf 15 [2] d3 12 [2] cf 3d }

  condition:
    any of them
}