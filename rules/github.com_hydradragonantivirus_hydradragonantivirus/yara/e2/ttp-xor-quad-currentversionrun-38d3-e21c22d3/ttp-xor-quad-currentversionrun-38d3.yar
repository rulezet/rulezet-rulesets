rule TTP_XOR_QUAD_CurrentVersionRun_38d3 {
  strings:
    $key_38d3 = { 6b bc [2] 4f b2 [2] 64 9e [2] 4a bc [2] 5e a7 [2] 51 bd [2] 4f a0 [2] 4d a1 [2] 56 a7 [2] 4a a0 [2] 56 8f }

  condition:
    any of them
}