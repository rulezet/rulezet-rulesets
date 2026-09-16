rule TTP_XOR_QUAD_CurrentVersionRun_0dd3 {
  strings:
    $key_0dd3 = { 5e bc [2] 7a b2 [2] 51 9e [2] 7f bc [2] 6b a7 [2] 64 bd [2] 7a a0 [2] 78 a1 [2] 63 a7 [2] 7f a0 [2] 63 8f }

  condition:
    any of them
}