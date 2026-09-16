rule TTP_XOR_QUAD_CurrentVersionRun_d4ca {
  strings:
    $key_d4ca = { 87 a5 [2] a3 ab [2] 88 87 [2] a6 a5 [2] b2 be [2] bd a4 [2] a3 b9 [2] a1 b8 [2] ba be [2] a6 b9 [2] ba 96 }

  condition:
    any of them
}