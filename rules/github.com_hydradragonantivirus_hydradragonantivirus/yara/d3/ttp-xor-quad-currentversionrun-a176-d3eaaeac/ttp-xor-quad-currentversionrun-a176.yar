rule TTP_XOR_QUAD_CurrentVersionRun_a176 {
  strings:
    $key_a176 = { f2 19 [2] d6 17 [2] fd 3b [2] d3 19 [2] c7 02 [2] c8 18 [2] d6 05 [2] d4 04 [2] cf 02 [2] d3 05 [2] cf 2a }

  condition:
    any of them
}