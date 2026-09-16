rule TTP_XOR_QUAD_CurrentVersionRun_56d0 {
  strings:
    $key_56d0 = { 05 bf [2] 21 b1 [2] 0a 9d [2] 24 bf [2] 30 a4 [2] 3f be [2] 21 a3 [2] 23 a2 [2] 38 a4 [2] 24 a3 [2] 38 8c }

  condition:
    any of them
}