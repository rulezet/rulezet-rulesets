rule TTP_XOR_QUAD_CurrentVersionRun_48c9 {
  strings:
    $key_48c9 = { 1b a6 [2] 3f a8 [2] 14 84 [2] 3a a6 [2] 2e bd [2] 21 a7 [2] 3f ba [2] 3d bb [2] 26 bd [2] 3a ba [2] 26 95 }

  condition:
    any of them
}