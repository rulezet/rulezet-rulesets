rule TTP_XOR_QUAD_CurrentVersionRun_46d2 {
  strings:
    $key_46d2 = { 15 bd [2] 31 b3 [2] 1a 9f [2] 34 bd [2] 20 a6 [2] 2f bc [2] 31 a1 [2] 33 a0 [2] 28 a6 [2] 34 a1 [2] 28 8e }

  condition:
    any of them
}