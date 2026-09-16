rule TTP_XOR_QUAD_CurrentVersionRun_dbd7 {
  strings:
    $key_dbd7 = { 88 b8 [2] ac b6 [2] 87 9a [2] a9 b8 [2] bd a3 [2] b2 b9 [2] ac a4 [2] ae a5 [2] b5 a3 [2] a9 a4 [2] b5 8b }

  condition:
    any of them
}