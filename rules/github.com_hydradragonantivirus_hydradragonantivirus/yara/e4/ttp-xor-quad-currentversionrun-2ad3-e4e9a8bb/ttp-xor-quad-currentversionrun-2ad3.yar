rule TTP_XOR_QUAD_CurrentVersionRun_2ad3 {
  strings:
    $key_2ad3 = { 79 bc [2] 5d b2 [2] 76 9e [2] 58 bc [2] 4c a7 [2] 43 bd [2] 5d a0 [2] 5f a1 [2] 44 a7 [2] 58 a0 [2] 44 8f }

  condition:
    any of them
}