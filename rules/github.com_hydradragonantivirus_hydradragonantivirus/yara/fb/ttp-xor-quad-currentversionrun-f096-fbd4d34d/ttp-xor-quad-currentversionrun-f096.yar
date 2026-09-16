rule TTP_XOR_QUAD_CurrentVersionRun_f096 {
  strings:
    $key_f096 = { a3 f9 [2] 87 f7 [2] ac db [2] 82 f9 [2] 96 e2 [2] 99 f8 [2] 87 e5 [2] 85 e4 [2] 9e e2 [2] 82 e5 [2] 9e ca }

  condition:
    any of them
}