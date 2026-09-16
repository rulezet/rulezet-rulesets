rule TTP_XOR_QUAD_CurrentVersionRun_a158 {
  strings:
    $key_a158 = { f2 37 [2] d6 39 [2] fd 15 [2] d3 37 [2] c7 2c [2] c8 36 [2] d6 2b [2] d4 2a [2] cf 2c [2] d3 2b [2] cf 04 }

  condition:
    any of them
}