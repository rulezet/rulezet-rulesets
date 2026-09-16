rule TTP_XOR_QUAD_CurrentVersionRun_20d2 {
  strings:
    $key_20d2 = { 73 bd [2] 57 b3 [2] 7c 9f [2] 52 bd [2] 46 a6 [2] 49 bc [2] 57 a1 [2] 55 a0 [2] 4e a6 [2] 52 a1 [2] 4e 8e }

  condition:
    any of them
}