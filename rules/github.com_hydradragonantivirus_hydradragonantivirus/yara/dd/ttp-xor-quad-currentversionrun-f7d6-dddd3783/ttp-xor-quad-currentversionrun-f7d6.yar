rule TTP_XOR_QUAD_CurrentVersionRun_f7d6 {
  strings:
    $key_f7d6 = { a4 b9 [2] 80 b7 [2] ab 9b [2] 85 b9 [2] 91 a2 [2] 9e b8 [2] 80 a5 [2] 82 a4 [2] 99 a2 [2] 85 a5 [2] 99 8a }

  condition:
    any of them
}