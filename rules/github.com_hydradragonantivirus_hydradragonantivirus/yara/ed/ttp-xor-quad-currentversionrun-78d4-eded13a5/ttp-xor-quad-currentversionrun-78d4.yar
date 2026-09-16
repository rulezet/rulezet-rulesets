rule TTP_XOR_QUAD_CurrentVersionRun_78d4 {
  strings:
    $key_78d4 = { 2b bb [2] 0f b5 [2] 24 99 [2] 0a bb [2] 1e a0 [2] 11 ba [2] 0f a7 [2] 0d a6 [2] 16 a0 [2] 0a a7 [2] 16 88 }

  condition:
    any of them
}