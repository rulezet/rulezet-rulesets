rule TTP_XOR_QUAD_CurrentVersionRun_5bd2 {
  strings:
    $key_5bd2 = { 08 bd [2] 2c b3 [2] 07 9f [2] 29 bd [2] 3d a6 [2] 32 bc [2] 2c a1 [2] 2e a0 [2] 35 a6 [2] 29 a1 [2] 35 8e }

  condition:
    any of them
}