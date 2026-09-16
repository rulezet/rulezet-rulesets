rule TTP_XOR_QUAD_CurrentVersionRun_f8d4 {
  strings:
    $key_f8d4 = { ab bb [2] 8f b5 [2] a4 99 [2] 8a bb [2] 9e a0 [2] 91 ba [2] 8f a7 [2] 8d a6 [2] 96 a0 [2] 8a a7 [2] 96 88 }

  condition:
    any of them
}