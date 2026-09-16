rule TTP_XOR_QUAD_CurrentVersionRun_22d0 {
  strings:
    $key_22d0 = { 71 bf [2] 55 b1 [2] 7e 9d [2] 50 bf [2] 44 a4 [2] 4b be [2] 55 a3 [2] 57 a2 [2] 4c a4 [2] 50 a3 [2] 4c 8c }

  condition:
    any of them
}