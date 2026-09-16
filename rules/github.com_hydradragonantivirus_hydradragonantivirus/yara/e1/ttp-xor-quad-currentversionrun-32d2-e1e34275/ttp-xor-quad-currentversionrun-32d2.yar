rule TTP_XOR_QUAD_CurrentVersionRun_32d2 {
  strings:
    $key_32d2 = { 61 bd [2] 45 b3 [2] 6e 9f [2] 40 bd [2] 54 a6 [2] 5b bc [2] 45 a1 [2] 47 a0 [2] 5c a6 [2] 40 a1 [2] 5c 8e }

  condition:
    any of them
}