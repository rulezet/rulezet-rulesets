rule TTP_XOR_QUAD_CurrentVersionRun_4bd2 {
  strings:
    $key_4bd2 = { 18 bd [2] 3c b3 [2] 17 9f [2] 39 bd [2] 2d a6 [2] 22 bc [2] 3c a1 [2] 3e a0 [2] 25 a6 [2] 39 a1 [2] 25 8e }

  condition:
    any of them
}