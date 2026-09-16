rule TTP_XOR_QUAD_CurrentVersionRun_22d2 {
  strings:
    $key_22d2 = { 71 bd [2] 55 b3 [2] 7e 9f [2] 50 bd [2] 44 a6 [2] 4b bc [2] 55 a1 [2] 57 a0 [2] 4c a6 [2] 50 a1 [2] 4c 8e }

  condition:
    any of them
}