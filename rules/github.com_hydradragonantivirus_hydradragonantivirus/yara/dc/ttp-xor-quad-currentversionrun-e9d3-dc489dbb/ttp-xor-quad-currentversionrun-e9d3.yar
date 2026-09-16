rule TTP_XOR_QUAD_CurrentVersionRun_e9d3 {
  strings:
    $key_e9d3 = { ba bc [2] 9e b2 [2] b5 9e [2] 9b bc [2] 8f a7 [2] 80 bd [2] 9e a0 [2] 9c a1 [2] 87 a7 [2] 9b a0 [2] 87 8f }

  condition:
    any of them
}