rule TTP_XOR_QUAD_CurrentVersionRun_2ed3 {
  strings:
    $key_2ed3 = { 7d bc [2] 59 b2 [2] 72 9e [2] 5c bc [2] 48 a7 [2] 47 bd [2] 59 a0 [2] 5b a1 [2] 40 a7 [2] 5c a0 [2] 40 8f }

  condition:
    any of them
}