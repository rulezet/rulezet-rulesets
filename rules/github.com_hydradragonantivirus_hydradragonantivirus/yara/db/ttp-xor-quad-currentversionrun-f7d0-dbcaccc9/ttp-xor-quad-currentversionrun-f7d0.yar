rule TTP_XOR_QUAD_CurrentVersionRun_f7d0 {
  strings:
    $key_f7d0 = { a4 bf [2] 80 b1 [2] ab 9d [2] 85 bf [2] 91 a4 [2] 9e be [2] 80 a3 [2] 82 a2 [2] 99 a4 [2] 85 a3 [2] 99 8c }

  condition:
    any of them
}