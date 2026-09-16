rule TTP_XOR_QUAD_CurrentVersionRun_d1d1 {
  strings:
    $key_d1d1 = { 82 be [2] a6 b0 [2] 8d 9c [2] a3 be [2] b7 a5 [2] b8 bf [2] a6 a2 [2] a4 a3 [2] bf a5 [2] a3 a2 [2] bf 8d }

  condition:
    any of them
}