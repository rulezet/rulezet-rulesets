rule TTP_XOR_QUAD_CurrentVersionRun_dbd5 {
  strings:
    $key_dbd5 = { 88 ba [2] ac b4 [2] 87 98 [2] a9 ba [2] bd a1 [2] b2 bb [2] ac a6 [2] ae a7 [2] b5 a1 [2] a9 a6 [2] b5 89 }

  condition:
    any of them
}