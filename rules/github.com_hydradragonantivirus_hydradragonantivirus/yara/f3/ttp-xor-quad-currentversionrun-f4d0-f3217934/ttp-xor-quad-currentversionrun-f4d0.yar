rule TTP_XOR_QUAD_CurrentVersionRun_f4d0 {
  strings:
    $key_f4d0 = { a7 bf [2] 83 b1 [2] a8 9d [2] 86 bf [2] 92 a4 [2] 9d be [2] 83 a3 [2] 81 a2 [2] 9a a4 [2] 86 a3 [2] 9a 8c }

  condition:
    any of them
}