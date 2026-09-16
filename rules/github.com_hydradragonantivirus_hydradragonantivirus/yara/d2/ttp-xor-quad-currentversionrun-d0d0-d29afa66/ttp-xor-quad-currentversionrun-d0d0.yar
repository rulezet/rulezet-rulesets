rule TTP_XOR_QUAD_CurrentVersionRun_d0d0 {
  strings:
    $key_d0d0 = { 83 bf [2] a7 b1 [2] 8c 9d [2] a2 bf [2] b6 a4 [2] b9 be [2] a7 a3 [2] a5 a2 [2] be a4 [2] a2 a3 [2] be 8c }

  condition:
    any of them
}