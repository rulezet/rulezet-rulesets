rule TTP_XOR_QUAD_CurrentVersionRun_a1ea {
  strings:
    $key_a1ea = { f2 85 [2] d6 8b [2] fd a7 [2] d3 85 [2] c7 9e [2] c8 84 [2] d6 99 [2] d4 98 [2] cf 9e [2] d3 99 [2] cf b6 }

  condition:
    any of them
}