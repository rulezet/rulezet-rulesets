rule TTP_XOR_QUAD_CurrentVersionRun_fad3 {
  strings:
    $key_fad3 = { a9 bc [2] 8d b2 [2] a6 9e [2] 88 bc [2] 9c a7 [2] 93 bd [2] 8d a0 [2] 8f a1 [2] 94 a7 [2] 88 a0 [2] 94 8f }

  condition:
    any of them
}