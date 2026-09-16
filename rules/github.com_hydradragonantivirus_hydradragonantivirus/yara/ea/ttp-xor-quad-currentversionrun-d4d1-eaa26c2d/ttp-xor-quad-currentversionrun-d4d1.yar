rule TTP_XOR_QUAD_CurrentVersionRun_d4d1 {
  strings:
    $key_d4d1 = { 87 be [2] a3 b0 [2] 88 9c [2] a6 be [2] b2 a5 [2] bd bf [2] a3 a2 [2] a1 a3 [2] ba a5 [2] a6 a2 [2] ba 8d }

  condition:
    any of them
}