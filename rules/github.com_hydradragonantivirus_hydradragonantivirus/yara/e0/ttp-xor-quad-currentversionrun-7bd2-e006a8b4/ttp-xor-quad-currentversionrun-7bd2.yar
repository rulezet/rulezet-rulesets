rule TTP_XOR_QUAD_CurrentVersionRun_7bd2 {
  strings:
    $key_7bd2 = { 28 bd [2] 0c b3 [2] 27 9f [2] 09 bd [2] 1d a6 [2] 12 bc [2] 0c a1 [2] 0e a0 [2] 15 a6 [2] 09 a1 [2] 15 8e }

  condition:
    any of them
}