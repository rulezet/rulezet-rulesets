rule TTP_XOR_QUAD_CurrentVersionRun_a154 {
  strings:
    $key_a154 = { f2 3b [2] d6 35 [2] fd 19 [2] d3 3b [2] c7 20 [2] c8 3a [2] d6 27 [2] d4 26 [2] cf 20 [2] d3 27 [2] cf 08 }

  condition:
    any of them
}