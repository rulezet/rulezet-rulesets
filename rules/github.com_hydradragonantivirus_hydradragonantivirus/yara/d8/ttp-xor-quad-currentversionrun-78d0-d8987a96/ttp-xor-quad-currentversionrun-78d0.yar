rule TTP_XOR_QUAD_CurrentVersionRun_78d0 {
  strings:
    $key_78d0 = { 2b bf [2] 0f b1 [2] 24 9d [2] 0a bf [2] 1e a4 [2] 11 be [2] 0f a3 [2] 0d a2 [2] 16 a4 [2] 0a a3 [2] 16 8c }

  condition:
    any of them
}