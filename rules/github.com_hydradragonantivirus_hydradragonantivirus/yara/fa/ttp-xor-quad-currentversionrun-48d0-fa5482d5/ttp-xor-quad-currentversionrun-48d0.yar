rule TTP_XOR_QUAD_CurrentVersionRun_48d0 {
  strings:
    $key_48d0 = { 1b bf [2] 3f b1 [2] 14 9d [2] 3a bf [2] 2e a4 [2] 21 be [2] 3f a3 [2] 3d a2 [2] 26 a4 [2] 3a a3 [2] 26 8c }

  condition:
    any of them
}