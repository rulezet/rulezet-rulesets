rule TTP_XOR_QUAD_CurrentVersionRun_f7c6 {
  strings:
    $key_f7c6 = { a4 a9 [2] 80 a7 [2] ab 8b [2] 85 a9 [2] 91 b2 [2] 9e a8 [2] 80 b5 [2] 82 b4 [2] 99 b2 [2] 85 b5 [2] 99 9a }

  condition:
    any of them
}