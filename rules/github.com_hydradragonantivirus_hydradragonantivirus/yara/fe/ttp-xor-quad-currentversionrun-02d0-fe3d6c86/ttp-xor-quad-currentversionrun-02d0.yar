rule TTP_XOR_QUAD_CurrentVersionRun_02d0 {
  strings:
    $key_02d0 = { 51 bf [2] 75 b1 [2] 5e 9d [2] 70 bf [2] 64 a4 [2] 6b be [2] 75 a3 [2] 77 a2 [2] 6c a4 [2] 70 a3 [2] 6c 8c }

  condition:
    any of them
}