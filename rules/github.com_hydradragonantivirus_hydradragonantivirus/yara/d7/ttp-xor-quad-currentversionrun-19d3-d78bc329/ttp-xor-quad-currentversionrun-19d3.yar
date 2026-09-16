rule TTP_XOR_QUAD_CurrentVersionRun_19d3 {
  strings:
    $key_19d3 = { 4a bc [2] 6e b2 [2] 45 9e [2] 6b bc [2] 7f a7 [2] 70 bd [2] 6e a0 [2] 6c a1 [2] 77 a7 [2] 6b a0 [2] 77 8f }

  condition:
    any of them
}