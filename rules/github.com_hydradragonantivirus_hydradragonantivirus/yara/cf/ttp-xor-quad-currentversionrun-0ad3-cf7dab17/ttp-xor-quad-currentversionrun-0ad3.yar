rule TTP_XOR_QUAD_CurrentVersionRun_0ad3 {
  strings:
    $key_0ad3 = { 59 bc [2] 7d b2 [2] 56 9e [2] 78 bc [2] 6c a7 [2] 63 bd [2] 7d a0 [2] 7f a1 [2] 64 a7 [2] 78 a0 [2] 64 8f }

  condition:
    any of them
}