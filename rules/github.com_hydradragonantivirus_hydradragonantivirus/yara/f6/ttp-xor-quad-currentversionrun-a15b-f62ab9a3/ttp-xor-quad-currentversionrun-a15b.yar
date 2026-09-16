rule TTP_XOR_QUAD_CurrentVersionRun_a15b {
  strings:
    $key_a15b = { f2 34 [2] d6 3a [2] fd 16 [2] d3 34 [2] c7 2f [2] c8 35 [2] d6 28 [2] d4 29 [2] cf 2f [2] d3 28 [2] cf 07 }

  condition:
    any of them
}