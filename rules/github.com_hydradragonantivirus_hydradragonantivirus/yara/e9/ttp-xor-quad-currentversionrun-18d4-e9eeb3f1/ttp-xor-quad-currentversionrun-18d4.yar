rule TTP_XOR_QUAD_CurrentVersionRun_18d4 {
  strings:
    $key_18d4 = { 4b bb [2] 6f b5 [2] 44 99 [2] 6a bb [2] 7e a0 [2] 71 ba [2] 6f a7 [2] 6d a6 [2] 76 a0 [2] 6a a7 [2] 76 88 }

  condition:
    any of them
}