rule TTP_XOR_QUAD_CurrentVersionRun_12d0 {
  strings:
    $key_12d0 = { 41 bf [2] 65 b1 [2] 4e 9d [2] 60 bf [2] 74 a4 [2] 7b be [2] 65 a3 [2] 67 a2 [2] 7c a4 [2] 60 a3 [2] 7c 8c }

  condition:
    any of them
}