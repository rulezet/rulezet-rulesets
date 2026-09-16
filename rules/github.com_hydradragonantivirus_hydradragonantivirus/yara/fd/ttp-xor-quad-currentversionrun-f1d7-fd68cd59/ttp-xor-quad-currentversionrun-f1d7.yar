rule TTP_XOR_QUAD_CurrentVersionRun_f1d7 {
  strings:
    $key_f1d7 = { a2 b8 [2] 86 b6 [2] ad 9a [2] 83 b8 [2] 97 a3 [2] 98 b9 [2] 86 a4 [2] 84 a5 [2] 9f a3 [2] 83 a4 [2] 9f 8b }

  condition:
    any of them
}