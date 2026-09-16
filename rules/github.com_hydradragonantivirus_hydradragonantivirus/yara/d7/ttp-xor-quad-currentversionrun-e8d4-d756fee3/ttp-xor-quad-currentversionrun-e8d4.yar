rule TTP_XOR_QUAD_CurrentVersionRun_e8d4 {
  strings:
    $key_e8d4 = { bb bb [2] 9f b5 [2] b4 99 [2] 9a bb [2] 8e a0 [2] 81 ba [2] 9f a7 [2] 9d a6 [2] 86 a0 [2] 9a a7 [2] 86 88 }

  condition:
    any of them
}