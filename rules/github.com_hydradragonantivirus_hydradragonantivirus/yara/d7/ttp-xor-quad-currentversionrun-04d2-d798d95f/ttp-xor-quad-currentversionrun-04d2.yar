rule TTP_XOR_QUAD_CurrentVersionRun_04d2 {
  strings:
    $key_04d2 = { 57 bd [2] 73 b3 [2] 58 9f [2] 76 bd [2] 62 a6 [2] 6d bc [2] 73 a1 [2] 71 a0 [2] 6a a6 [2] 76 a1 [2] 6a 8e }

  condition:
    any of them
}