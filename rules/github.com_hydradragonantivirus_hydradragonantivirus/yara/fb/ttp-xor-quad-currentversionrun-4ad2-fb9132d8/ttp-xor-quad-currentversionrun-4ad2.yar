rule TTP_XOR_QUAD_CurrentVersionRun_4ad2 {
  strings:
    $key_4ad2 = { 19 bd [2] 3d b3 [2] 16 9f [2] 38 bd [2] 2c a6 [2] 23 bc [2] 3d a1 [2] 3f a0 [2] 24 a6 [2] 38 a1 [2] 24 8e }

  condition:
    any of them
}