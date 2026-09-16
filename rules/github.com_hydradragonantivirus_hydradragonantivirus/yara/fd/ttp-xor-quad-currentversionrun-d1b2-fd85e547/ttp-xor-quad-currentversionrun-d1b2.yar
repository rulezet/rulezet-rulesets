rule TTP_XOR_QUAD_CurrentVersionRun_d1b2 {
  strings:
    $key_d1b2 = { 82 dd [2] a6 d3 [2] 8d ff [2] a3 dd [2] b7 c6 [2] b8 dc [2] a6 c1 [2] a4 c0 [2] bf c6 [2] a3 c1 [2] bf ee }

  condition:
    any of them
}