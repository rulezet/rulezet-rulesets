rule TTP_XOR_QUAD_CurrentVersionRun_48d2 {
  strings:
    $key_48d2 = { 1b bd [2] 3f b3 [2] 14 9f [2] 3a bd [2] 2e a6 [2] 21 bc [2] 3f a1 [2] 3d a0 [2] 26 a6 [2] 3a a1 [2] 26 8e }

  condition:
    any of them
}