rule TTP_XOR_QUAD_CurrentVersionRun_6ad2 {
  strings:
    $key_6ad2 = { 39 bd [2] 1d b3 [2] 36 9f [2] 18 bd [2] 0c a6 [2] 03 bc [2] 1d a1 [2] 1f a0 [2] 04 a6 [2] 18 a1 [2] 04 8e }

  condition:
    any of them
}