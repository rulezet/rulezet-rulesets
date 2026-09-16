rule TTP_XOR_QUAD_CurrentVersionRun_48d4 {
  strings:
    $key_48d4 = { 1b bb [2] 3f b5 [2] 14 99 [2] 3a bb [2] 2e a0 [2] 21 ba [2] 3f a7 [2] 3d a6 [2] 26 a0 [2] 3a a7 [2] 26 88 }

  condition:
    any of them
}