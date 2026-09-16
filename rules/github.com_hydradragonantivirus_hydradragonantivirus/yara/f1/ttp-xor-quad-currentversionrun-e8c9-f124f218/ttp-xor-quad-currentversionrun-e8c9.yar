rule TTP_XOR_QUAD_CurrentVersionRun_e8c9 {
  strings:
    $key_e8c9 = { bb a6 [2] 9f a8 [2] b4 84 [2] 9a a6 [2] 8e bd [2] 81 a7 [2] 9f ba [2] 9d bb [2] 86 bd [2] 9a ba [2] 86 95 }

  condition:
    any of them
}