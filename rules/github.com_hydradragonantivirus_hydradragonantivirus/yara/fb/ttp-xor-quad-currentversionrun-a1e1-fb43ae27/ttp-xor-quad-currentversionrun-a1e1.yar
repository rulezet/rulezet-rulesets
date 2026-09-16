rule TTP_XOR_QUAD_CurrentVersionRun_a1e1 {
  strings:
    $key_a1e1 = { f2 8e [2] d6 80 [2] fd ac [2] d3 8e [2] c7 95 [2] c8 8f [2] d6 92 [2] d4 93 [2] cf 95 [2] d3 92 [2] cf bd }

  condition:
    any of them
}