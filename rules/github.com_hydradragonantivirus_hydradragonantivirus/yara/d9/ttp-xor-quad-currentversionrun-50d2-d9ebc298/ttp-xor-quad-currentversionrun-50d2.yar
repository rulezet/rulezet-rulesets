rule TTP_XOR_QUAD_CurrentVersionRun_50d2 {
  strings:
    $key_50d2 = { 03 bd [2] 27 b3 [2] 0c 9f [2] 22 bd [2] 36 a6 [2] 39 bc [2] 27 a1 [2] 25 a0 [2] 3e a6 [2] 22 a1 [2] 3e 8e }

  condition:
    any of them
}