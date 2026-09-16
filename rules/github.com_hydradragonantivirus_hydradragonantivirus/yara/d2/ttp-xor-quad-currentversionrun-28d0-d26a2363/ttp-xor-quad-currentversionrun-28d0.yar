rule TTP_XOR_QUAD_CurrentVersionRun_28d0 {
  strings:
    $key_28d0 = { 7b bf [2] 5f b1 [2] 74 9d [2] 5a bf [2] 4e a4 [2] 41 be [2] 5f a3 [2] 5d a2 [2] 46 a4 [2] 5a a3 [2] 46 8c }

  condition:
    any of them
}