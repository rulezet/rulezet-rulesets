rule TTP_XOR_QUAD_CurrentVersionRun_49d4 {
  strings:
    $key_49d4 = { 1a bb [2] 3e b5 [2] 15 99 [2] 3b bb [2] 2f a0 [2] 20 ba [2] 3e a7 [2] 3c a6 [2] 27 a0 [2] 3b a7 [2] 27 88 }

  condition:
    any of them
}