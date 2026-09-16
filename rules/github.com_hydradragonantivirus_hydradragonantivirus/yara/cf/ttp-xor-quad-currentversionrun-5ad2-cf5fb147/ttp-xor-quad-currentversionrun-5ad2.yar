rule TTP_XOR_QUAD_CurrentVersionRun_5ad2 {
  strings:
    $key_5ad2 = { 09 bd [2] 2d b3 [2] 06 9f [2] 28 bd [2] 3c a6 [2] 33 bc [2] 2d a1 [2] 2f a0 [2] 34 a6 [2] 28 a1 [2] 34 8e }

  condition:
    any of them
}