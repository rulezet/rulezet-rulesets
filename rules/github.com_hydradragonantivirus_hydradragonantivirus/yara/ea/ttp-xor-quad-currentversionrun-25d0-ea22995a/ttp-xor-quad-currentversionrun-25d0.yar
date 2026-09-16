rule TTP_XOR_QUAD_CurrentVersionRun_25d0 {
  strings:
    $key_25d0 = { 76 bf [2] 52 b1 [2] 79 9d [2] 57 bf [2] 43 a4 [2] 4c be [2] 52 a3 [2] 50 a2 [2] 4b a4 [2] 57 a3 [2] 4b 8c }

  condition:
    any of them
}