rule TTP_XOR_QUAD_CurrentVersionRun_60d0 {
  strings:
    $key_60d0 = { 33 bf [2] 17 b1 [2] 3c 9d [2] 12 bf [2] 06 a4 [2] 09 be [2] 17 a3 [2] 15 a2 [2] 0e a4 [2] 12 a3 [2] 0e 8c }

  condition:
    any of them
}