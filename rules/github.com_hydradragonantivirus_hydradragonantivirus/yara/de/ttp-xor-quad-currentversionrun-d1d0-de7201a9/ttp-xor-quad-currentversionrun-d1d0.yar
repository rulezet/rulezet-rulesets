rule TTP_XOR_QUAD_CurrentVersionRun_d1d0 {
  strings:
    $key_d1d0 = { 82 bf [2] a6 b1 [2] 8d 9d [2] a3 bf [2] b7 a4 [2] b8 be [2] a6 a3 [2] a4 a2 [2] bf a4 [2] a3 a3 [2] bf 8c }

  condition:
    any of them
}