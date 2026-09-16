rule TTP_XOR_QUAD_CurrentVersionRun_00d0 {
  strings:
    $key_00d0 = { 53 bf [2] 77 b1 [2] 5c 9d [2] 72 bf [2] 66 a4 [2] 69 be [2] 77 a3 [2] 75 a2 [2] 6e a4 [2] 72 a3 [2] 6e 8c }

  condition:
    any of them
}