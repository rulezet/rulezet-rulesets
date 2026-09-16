rule TTP_XOR_QUAD_CurrentVersionRun_68c9 {
  strings:
    $key_68c9 = { 3b a6 [2] 1f a8 [2] 34 84 [2] 1a a6 [2] 0e bd [2] 01 a7 [2] 1f ba [2] 1d bb [2] 06 bd [2] 1a ba [2] 06 95 }

  condition:
    any of them
}