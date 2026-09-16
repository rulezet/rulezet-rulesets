rule TTP_XOR_QUAD_CurrentVersionRun_78c9 {
  strings:
    $key_78c9 = { 2b a6 [2] 0f a8 [2] 24 84 [2] 0a a6 [2] 1e bd [2] 11 a7 [2] 0f ba [2] 0d bb [2] 16 bd [2] 0a ba [2] 16 95 }

  condition:
    any of them
}