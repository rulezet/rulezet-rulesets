rule TTP_XOR_QUAD_CurrentVersionRun_a17c {
  strings:
    $key_a17c = { f2 13 [2] d6 1d [2] fd 31 [2] d3 13 [2] c7 08 [2] c8 12 [2] d6 0f [2] d4 0e [2] cf 08 [2] d3 0f [2] cf 20 }

  condition:
    any of them
}