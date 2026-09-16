rule TTP_XOR_QUAD_CurrentVersionRun_b3ea {
  strings:
    $key_b3ea = { e0 85 [2] c4 8b [2] ef a7 [2] c1 85 [2] d5 9e [2] da 84 [2] c4 99 [2] c6 98 [2] dd 9e [2] c1 99 [2] dd b6 }

  condition:
    any of them
}