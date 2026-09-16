rule TTP_XOR_QUAD_CurrentVersionRun_69d3 {
  strings:
    $key_69d3 = { 3a bc [2] 1e b2 [2] 35 9e [2] 1b bc [2] 0f a7 [2] 00 bd [2] 1e a0 [2] 1c a1 [2] 07 a7 [2] 1b a0 [2] 07 8f }

  condition:
    any of them
}