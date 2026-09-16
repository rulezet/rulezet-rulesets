rule TTP_XOR_QUAD_CurrentVersionRun_07d2 {
  strings:
    $key_07d2 = { 54 bd [2] 70 b3 [2] 5b 9f [2] 75 bd [2] 61 a6 [2] 6e bc [2] 70 a1 [2] 72 a0 [2] 69 a6 [2] 75 a1 [2] 69 8e }

  condition:
    any of them
}