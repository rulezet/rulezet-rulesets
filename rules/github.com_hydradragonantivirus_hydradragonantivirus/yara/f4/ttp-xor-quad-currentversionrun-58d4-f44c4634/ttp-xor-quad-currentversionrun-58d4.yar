rule TTP_XOR_QUAD_CurrentVersionRun_58d4 {
  strings:
    $key_58d4 = { 0b bb [2] 2f b5 [2] 04 99 [2] 2a bb [2] 3e a0 [2] 31 ba [2] 2f a7 [2] 2d a6 [2] 36 a0 [2] 2a a7 [2] 36 88 }

  condition:
    any of them
}