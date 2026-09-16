rule TTP_XOR_QUAD_CurrentVersionRun_f0d2 {
  strings:
    $key_f0d2 = { a3 bd [2] 87 b3 [2] ac 9f [2] 82 bd [2] 96 a6 [2] 99 bc [2] 87 a1 [2] 85 a0 [2] 9e a6 [2] 82 a1 [2] 9e 8e }

  condition:
    any of them
}