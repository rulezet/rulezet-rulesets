rule TTP_XOR_QUAD_CurrentVersionRun_65d0 {
  strings:
    $key_65d0 = { 36 bf [2] 12 b1 [2] 39 9d [2] 17 bf [2] 03 a4 [2] 0c be [2] 12 a3 [2] 10 a2 [2] 0b a4 [2] 17 a3 [2] 0b 8c }

  condition:
    any of them
}