rule TTP_XOR_QUAD_CurrentVersionRun_f2d2 {
  strings:
    $key_f2d2 = { a1 bd [2] 85 b3 [2] ae 9f [2] 80 bd [2] 94 a6 [2] 9b bc [2] 85 a1 [2] 87 a0 [2] 9c a6 [2] 80 a1 [2] 9c 8e }

  condition:
    any of them
}