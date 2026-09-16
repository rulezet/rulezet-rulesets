rule TTP_XOR_QUAD_CurrentVersionRun_a1f3 {
  strings:
    $key_a1f3 = { f2 9c [2] d6 92 [2] fd be [2] d3 9c [2] c7 87 [2] c8 9d [2] d6 80 [2] d4 81 [2] cf 87 [2] d3 80 [2] cf af }

  condition:
    any of them
}