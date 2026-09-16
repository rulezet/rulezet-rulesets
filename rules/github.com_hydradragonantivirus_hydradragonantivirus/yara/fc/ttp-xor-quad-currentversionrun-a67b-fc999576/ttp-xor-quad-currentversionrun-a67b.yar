rule TTP_XOR_QUAD_CurrentVersionRun_a67b {
  strings:
    $key_a67b = { f5 14 [2] d1 1a [2] fa 36 [2] d4 14 [2] c0 0f [2] cf 15 [2] d1 08 [2] d3 09 [2] c8 0f [2] d4 08 [2] c8 27 }

  condition:
    any of them
}