rule TTP_XOR_QUAD_CurrentVersionRun_7bd0 {
  strings:
    $key_7bd0 = { 28 bf [2] 0c b1 [2] 27 9d [2] 09 bf [2] 1d a4 [2] 12 be [2] 0c a3 [2] 0e a2 [2] 15 a4 [2] 09 a3 [2] 15 8c }

  condition:
    any of them
}