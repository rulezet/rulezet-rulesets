rule TTP_XOR_QUAD_CurrentVersionRun_d4c4 {
  strings:
    $key_d4c4 = { 87 ab [2] a3 a5 [2] 88 89 [2] a6 ab [2] b2 b0 [2] bd aa [2] a3 b7 [2] a1 b6 [2] ba b0 [2] a6 b7 [2] ba 98 }

  condition:
    any of them
}