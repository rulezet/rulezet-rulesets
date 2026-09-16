rule TTP_XOR_QUAD_CurrentVersionRun_1bd3 {
  strings:
    $key_1bd3 = { 48 bc [2] 6c b2 [2] 47 9e [2] 69 bc [2] 7d a7 [2] 72 bd [2] 6c a0 [2] 6e a1 [2] 75 a7 [2] 69 a0 [2] 75 8f }

  condition:
    any of them
}