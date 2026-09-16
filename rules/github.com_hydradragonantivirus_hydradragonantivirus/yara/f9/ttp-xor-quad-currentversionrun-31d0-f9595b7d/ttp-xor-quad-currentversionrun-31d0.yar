rule TTP_XOR_QUAD_CurrentVersionRun_31d0 {
  strings:
    $key_31d0 = { 62 bf [2] 46 b1 [2] 6d 9d [2] 43 bf [2] 57 a4 [2] 58 be [2] 46 a3 [2] 44 a2 [2] 5f a4 [2] 43 a3 [2] 5f 8c }

  condition:
    any of them
}