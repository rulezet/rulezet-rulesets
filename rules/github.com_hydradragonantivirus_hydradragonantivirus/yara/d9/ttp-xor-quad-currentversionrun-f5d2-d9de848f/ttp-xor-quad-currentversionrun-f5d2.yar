rule TTP_XOR_QUAD_CurrentVersionRun_f5d2 {
  strings:
    $key_f5d2 = { a6 bd [2] 82 b3 [2] a9 9f [2] 87 bd [2] 93 a6 [2] 9c bc [2] 82 a1 [2] 80 a0 [2] 9b a6 [2] 87 a1 [2] 9b 8e }

  condition:
    any of them
}