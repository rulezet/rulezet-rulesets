rule TTP_XOR_QUAD_CurrentVersionRun_f1d0 {
  strings:
    $key_f1d0 = { a2 bf [2] 86 b1 [2] ad 9d [2] 83 bf [2] 97 a4 [2] 98 be [2] 86 a3 [2] 84 a2 [2] 9f a4 [2] 83 a3 [2] 9f 8c }

  condition:
    any of them
}