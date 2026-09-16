rule TTP_XOR_QUAD_CurrentVersionRun_09d4 {
  strings:
    $key_09d4 = { 5a bb [2] 7e b5 [2] 55 99 [2] 7b bb [2] 6f a0 [2] 60 ba [2] 7e a7 [2] 7c a6 [2] 67 a0 [2] 7b a7 [2] 67 88 }

  condition:
    any of them
}