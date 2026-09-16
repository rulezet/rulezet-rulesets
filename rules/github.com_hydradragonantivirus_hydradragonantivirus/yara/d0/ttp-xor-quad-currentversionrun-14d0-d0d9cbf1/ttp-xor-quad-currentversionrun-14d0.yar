rule TTP_XOR_QUAD_CurrentVersionRun_14d0 {
  strings:
    $key_14d0 = { 47 bf [2] 63 b1 [2] 48 9d [2] 66 bf [2] 72 a4 [2] 7d be [2] 63 a3 [2] 61 a2 [2] 7a a4 [2] 66 a3 [2] 7a 8c }

  condition:
    any of them
}