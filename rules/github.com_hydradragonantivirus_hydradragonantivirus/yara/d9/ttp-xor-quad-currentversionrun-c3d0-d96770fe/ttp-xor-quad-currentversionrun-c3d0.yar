rule TTP_XOR_QUAD_CurrentVersionRun_c3d0 {
  strings:
    $key_c3d0 = { 90 bf [2] b4 b1 [2] 9f 9d [2] b1 bf [2] a5 a4 [2] aa be [2] b4 a3 [2] b6 a2 [2] ad a4 [2] b1 a3 [2] ad 8c }

  condition:
    any of them
}