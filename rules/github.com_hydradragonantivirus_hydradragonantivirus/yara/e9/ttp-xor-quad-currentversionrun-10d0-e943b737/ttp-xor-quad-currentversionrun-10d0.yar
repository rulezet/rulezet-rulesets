rule TTP_XOR_QUAD_CurrentVersionRun_10d0 {
  strings:
    $key_10d0 = { 43 bf [2] 67 b1 [2] 4c 9d [2] 62 bf [2] 76 a4 [2] 79 be [2] 67 a3 [2] 65 a2 [2] 7e a4 [2] 62 a3 [2] 7e 8c }

  condition:
    any of them
}