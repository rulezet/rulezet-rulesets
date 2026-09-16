rule TTP_XOR_QUAD_CurrentVersionRun_d7d0 {
  strings:
    $key_d7d0 = { 84 bf [2] a0 b1 [2] 8b 9d [2] a5 bf [2] b1 a4 [2] be be [2] a0 a3 [2] a2 a2 [2] b9 a4 [2] a5 a3 [2] b9 8c }

  condition:
    any of them
}