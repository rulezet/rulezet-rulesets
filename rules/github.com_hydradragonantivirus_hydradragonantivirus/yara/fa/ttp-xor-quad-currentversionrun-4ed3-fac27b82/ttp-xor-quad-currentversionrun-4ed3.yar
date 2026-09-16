rule TTP_XOR_QUAD_CurrentVersionRun_4ed3 {
  strings:
    $key_4ed3 = { 1d bc [2] 39 b2 [2] 12 9e [2] 3c bc [2] 28 a7 [2] 27 bd [2] 39 a0 [2] 3b a1 [2] 20 a7 [2] 3c a0 [2] 20 8f }

  condition:
    any of them
}